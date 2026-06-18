/** Auto-generated */
package me.bechberger.ebpf.runtime;

import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.InlineUnion;
import me.bechberger.ebpf.annotations.Offset;
import me.bechberger.ebpf.annotations.OriginalName;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.ebpf.type.Struct;
import me.bechberger.ebpf.type.TypedEnum;
import me.bechberger.ebpf.type.TypedefBase;
import me.bechberger.ebpf.type.Union;
import org.jetbrains.annotations.Nullable;
import static me.bechberger.ebpf.runtime.AaDefinitions.*;
import static me.bechberger.ebpf.runtime.AafsDefinitions.*;
import static me.bechberger.ebpf.runtime.Aat2870Definitions.*;
import static me.bechberger.ebpf.runtime.AccountDefinitions.*;
import static me.bechberger.ebpf.runtime.AcctDefinitions.*;
import static me.bechberger.ebpf.runtime.AcompDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiphpDefinitions.*;
import static me.bechberger.ebpf.runtime.ActionDefinitions.*;
import static me.bechberger.ebpf.runtime.ActiveDefinitions.*;
import static me.bechberger.ebpf.runtime.AddDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrconfDefinitions.*;
import static me.bechberger.ebpf.runtime.AdjustDefinitions.*;
import static me.bechberger.ebpf.runtime.AdlDefinitions.*;
import static me.bechberger.ebpf.runtime.Adp5520Definitions.*;
import static me.bechberger.ebpf.runtime.AdvisorDefinitions.*;
import static me.bechberger.ebpf.runtime.AeadDefinitions.*;
import static me.bechberger.ebpf.runtime.AerDefinitions.*;
import static me.bechberger.ebpf.runtime.AgpDefinitions.*;
import static me.bechberger.ebpf.runtime.AhashDefinitions.*;
import static me.bechberger.ebpf.runtime.AioDefinitions.*;
import static me.bechberger.ebpf.runtime.AlarmDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocateDefinitions.*;
import static me.bechberger.ebpf.runtime.AmdDefinitions.*;
import static me.bechberger.ebpf.runtime.AmlDefinitions.*;
import static me.bechberger.ebpf.runtime.AnonDefinitions.*;
import static me.bechberger.ebpf.runtime.ApeiDefinitions.*;
import static me.bechberger.ebpf.runtime.ApicDefinitions.*;
import static me.bechberger.ebpf.runtime.ApparmorDefinitions.*;
import static me.bechberger.ebpf.runtime.AppendDefinitions.*;
import static me.bechberger.ebpf.runtime.ApplyDefinitions.*;
import static me.bechberger.ebpf.runtime.ArchDefinitions.*;
import static me.bechberger.ebpf.runtime.ArenaDefinitions.*;
import static me.bechberger.ebpf.runtime.ArpDefinitions.*;
import static me.bechberger.ebpf.runtime.ArrayDefinitions.*;
import static me.bechberger.ebpf.runtime.Asn1Definitions.*;
import static me.bechberger.ebpf.runtime.AssocDefinitions.*;
import static me.bechberger.ebpf.runtime.AsymmetricDefinitions.*;
import static me.bechberger.ebpf.runtime.AsyncDefinitions.*;
import static me.bechberger.ebpf.runtime.AtaDefinitions.*;
import static me.bechberger.ebpf.runtime.AtkbdDefinitions.*;
import static me.bechberger.ebpf.runtime.AtomicDefinitions.*;
import static me.bechberger.ebpf.runtime.AttachDefinitions.*;
import static me.bechberger.ebpf.runtime.AttributeDefinitions.*;
import static me.bechberger.ebpf.runtime.AuditDefinitions.*;
import static me.bechberger.ebpf.runtime.AuxiliaryDefinitions.*;
import static me.bechberger.ebpf.runtime.AvailableDefinitions.*;
import static me.bechberger.ebpf.runtime.AvcDefinitions.*;
import static me.bechberger.ebpf.runtime.AvtabDefinitions.*;
import static me.bechberger.ebpf.runtime.BackingDefinitions.*;
import static me.bechberger.ebpf.runtime.BacklightDefinitions.*;
import static me.bechberger.ebpf.runtime.BadDefinitions.*;
import static me.bechberger.ebpf.runtime.BadblocksDefinitions.*;
import static me.bechberger.ebpf.runtime.BalanceDefinitions.*;
import static me.bechberger.ebpf.runtime.BalloonDefinitions.*;
import static me.bechberger.ebpf.runtime.BdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BdiDefinitions.*;
import static me.bechberger.ebpf.runtime.BgpioDefinitions.*;
import static me.bechberger.ebpf.runtime.BhDefinitions.*;
import static me.bechberger.ebpf.runtime.BindDefinitions.*;
import static me.bechberger.ebpf.runtime.BioDefinitions.*;
import static me.bechberger.ebpf.runtime.BitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.Blake2sDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkcgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkifDefinitions.*;
import static me.bechberger.ebpf.runtime.BlockDefinitions.*;
import static me.bechberger.ebpf.runtime.BloomDefinitions.*;
import static me.bechberger.ebpf.runtime.BootDefinitions.*;
import static me.bechberger.ebpf.runtime.BpfDefinitions.*;
import static me.bechberger.ebpf.runtime.BqlDefinitions.*;
import static me.bechberger.ebpf.runtime.BsgDefinitions.*;
import static me.bechberger.ebpf.runtime.BtfDefinitions.*;
import static me.bechberger.ebpf.runtime.BtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.BtsDefinitions.*;
import static me.bechberger.ebpf.runtime.BufferDefinitions.*;
import static me.bechberger.ebpf.runtime.BuildDefinitions.*;
import static me.bechberger.ebpf.runtime.BusDefinitions.*;
import static me.bechberger.ebpf.runtime.BytDefinitions.*;
import static me.bechberger.ebpf.runtime.CacheDefinitions.*;
import static me.bechberger.ebpf.runtime.CalcDefinitions.*;
import static me.bechberger.ebpf.runtime.CalculateDefinitions.*;
import static me.bechberger.ebpf.runtime.CalipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.CallDefinitions.*;
import static me.bechberger.ebpf.runtime.CanDefinitions.*;
import static me.bechberger.ebpf.runtime.CapDefinitions.*;
import static me.bechberger.ebpf.runtime.CcDefinitions.*;
import static me.bechberger.ebpf.runtime.CdevDefinitions.*;
import static me.bechberger.ebpf.runtime.CdromDefinitions.*;
import static me.bechberger.ebpf.runtime.CeaDefinitions.*;
import static me.bechberger.ebpf.runtime.Cfg80211Definitions.*;
import static me.bechberger.ebpf.runtime.Cgroup1Definitions.*;
import static me.bechberger.ebpf.runtime.CgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ChangeDefinitions.*;
import static me.bechberger.ebpf.runtime.ChargerDefinitions.*;
import static me.bechberger.ebpf.runtime.CheckDefinitions.*;
import static me.bechberger.ebpf.runtime.ChvDefinitions.*;
import static me.bechberger.ebpf.runtime.CipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.ClassDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanupDefinitions.*;
import static me.bechberger.ebpf.runtime.ClearDefinitions.*;
import static me.bechberger.ebpf.runtime.ClkDefinitions.*;
import static me.bechberger.ebpf.runtime.ClockeventsDefinitions.*;
import static me.bechberger.ebpf.runtime.ClocksourceDefinitions.*;
import static me.bechberger.ebpf.runtime.ClosureDefinitions.*;
import static me.bechberger.ebpf.runtime.CmaDefinitions.*;
import static me.bechberger.ebpf.runtime.CmciDefinitions.*;
import static me.bechberger.ebpf.runtime.CmdlineDefinitions.*;
import static me.bechberger.ebpf.runtime.CmisDefinitions.*;
import static me.bechberger.ebpf.runtime.CmosDefinitions.*;
import static me.bechberger.ebpf.runtime.CmpDefinitions.*;
import static me.bechberger.ebpf.runtime.CnDefinitions.*;
import static me.bechberger.ebpf.runtime.CollapseDefinitions.*;
import static me.bechberger.ebpf.runtime.CollectDefinitions.*;
import static me.bechberger.ebpf.runtime.CommonDefinitions.*;
import static me.bechberger.ebpf.runtime.CompactionDefinitions.*;
import static me.bechberger.ebpf.runtime.CompatDefinitions.*;
import static me.bechberger.ebpf.runtime.ComponentDefinitions.*;
import static me.bechberger.ebpf.runtime.ComputeDefinitions.*;
import static me.bechberger.ebpf.runtime.ConDefinitions.*;
import static me.bechberger.ebpf.runtime.CondDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigfsDefinitions.*;
import static me.bechberger.ebpf.runtime.ConsoleDefinitions.*;
import static me.bechberger.ebpf.runtime.ContextDefinitions.*;
import static me.bechberger.ebpf.runtime.ConvertDefinitions.*;
import static me.bechberger.ebpf.runtime.CookieDefinitions.*;
import static me.bechberger.ebpf.runtime.CopyDefinitions.*;
import static me.bechberger.ebpf.runtime.CoreDefinitions.*;
import static me.bechberger.ebpf.runtime.CoredumpDefinitions.*;
import static me.bechberger.ebpf.runtime.CountDefinitions.*;
import static me.bechberger.ebpf.runtime.CpciDefinitions.*;
import static me.bechberger.ebpf.runtime.CperDefinitions.*;
import static me.bechberger.ebpf.runtime.CppcDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuacctDefinitions.*;
import static me.bechberger.ebpf.runtime.CpufreqDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuhpDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuidleDefinitions.*;
import static me.bechberger.ebpf.runtime.CpumaskDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusetDefinitions.*;
import static me.bechberger.ebpf.runtime.CrashDefinitions.*;
import static me.bechberger.ebpf.runtime.CrbDefinitions.*;
import static me.bechberger.ebpf.runtime.Crc64Definitions.*;
import static me.bechberger.ebpf.runtime.CreateDefinitions.*;
import static me.bechberger.ebpf.runtime.CryptoDefinitions.*;
import static me.bechberger.ebpf.runtime.CrystalcoveDefinitions.*;
import static me.bechberger.ebpf.runtime.CssDefinitions.*;
import static me.bechberger.ebpf.runtime.CsumDefinitions.*;
import static me.bechberger.ebpf.runtime.CtDefinitions.*;
import static me.bechberger.ebpf.runtime.CtrlDefinitions.*;
import static me.bechberger.ebpf.runtime.CtxDefinitions.*;
import static me.bechberger.ebpf.runtime.CurrentDefinitions.*;
import static me.bechberger.ebpf.runtime.CxlDefinitions.*;
import static me.bechberger.ebpf.runtime.DDefinitions.*;
import static me.bechberger.ebpf.runtime.Da903xDefinitions.*;
import static me.bechberger.ebpf.runtime.Da9052Definitions.*;
import static me.bechberger.ebpf.runtime.Da9063Definitions.*;
import static me.bechberger.ebpf.runtime.DataDefinitions.*;
import static me.bechberger.ebpf.runtime.DaxDefinitions.*;
import static me.bechberger.ebpf.runtime.DbcDefinitions.*;
import static me.bechberger.ebpf.runtime.DbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbnlDefinitions.*;
import static me.bechberger.ebpf.runtime.DdDefinitions.*;
import static me.bechberger.ebpf.runtime.DdebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DeadlineDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugfsDefinitions.*;
import static me.bechberger.ebpf.runtime.DecDefinitions.*;
import static me.bechberger.ebpf.runtime.DefaultDefinitions.*;
import static me.bechberger.ebpf.runtime.DeferredDefinitions.*;
import static me.bechberger.ebpf.runtime.DeflateDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayacctDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayedDefinitions.*;
import static me.bechberger.ebpf.runtime.DeleteDefinitions.*;
import static me.bechberger.ebpf.runtime.DentryDefinitions.*;
import static me.bechberger.ebpf.runtime.DequeueDefinitions.*;
import static me.bechberger.ebpf.runtime.DescDefinitions.*;
import static me.bechberger.ebpf.runtime.DestroyDefinitions.*;
import static me.bechberger.ebpf.runtime.DetachDefinitions.*;
import static me.bechberger.ebpf.runtime.DevDefinitions.*;
import static me.bechberger.ebpf.runtime.DevcdDefinitions.*;
import static me.bechberger.ebpf.runtime.DevfreqDefinitions.*;
import static me.bechberger.ebpf.runtime.DeviceDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.DevmDefinitions.*;
import static me.bechberger.ebpf.runtime.DevptsDefinitions.*;
import static me.bechberger.ebpf.runtime.DevresDefinitions.*;
import static me.bechberger.ebpf.runtime.DhDefinitions.*;
import static me.bechberger.ebpf.runtime.DimDefinitions.*;
import static me.bechberger.ebpf.runtime.DisableDefinitions.*;
import static me.bechberger.ebpf.runtime.DiskDefinitions.*;
import static me.bechberger.ebpf.runtime.DispatchDefinitions.*;
import static me.bechberger.ebpf.runtime.DisplayidDefinitions.*;
import static me.bechberger.ebpf.runtime.DlDefinitions.*;
import static me.bechberger.ebpf.runtime.DmDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaDefinitions.*;
import static me.bechberger.ebpf.runtime.DmabufDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaengineDefinitions.*;
import static me.bechberger.ebpf.runtime.DmarDefinitions.*;
import static me.bechberger.ebpf.runtime.DmemDefinitions.*;
import static me.bechberger.ebpf.runtime.DmiDefinitions.*;
import static me.bechberger.ebpf.runtime.DnsDefinitions.*;
import static me.bechberger.ebpf.runtime.DoDefinitions.*;
import static me.bechberger.ebpf.runtime.DomainDefinitions.*;
import static me.bechberger.ebpf.runtime.DownDefinitions.*;
import static me.bechberger.ebpf.runtime.DpcDefinitions.*;
import static me.bechberger.ebpf.runtime.DpllDefinitions.*;
import static me.bechberger.ebpf.runtime.DpmDefinitions.*;
import static me.bechberger.ebpf.runtime.DquotDefinitions.*;
import static me.bechberger.ebpf.runtime.DrainDefinitions.*;
import static me.bechberger.ebpf.runtime.DrbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DriverDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmmDefinitions.*;
import static me.bechberger.ebpf.runtime.DropDefinitions.*;
import static me.bechberger.ebpf.runtime.DsaDefinitions.*;
import static me.bechberger.ebpf.runtime.DstDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyconDefinitions.*;
import static me.bechberger.ebpf.runtime.DumpDefinitions.*;
import static me.bechberger.ebpf.runtime.DupDefinitions.*;
import static me.bechberger.ebpf.runtime.DvdDefinitions.*;
import static me.bechberger.ebpf.runtime.DwDefinitions.*;
import static me.bechberger.ebpf.runtime.Dwc2Definitions.*;
import static me.bechberger.ebpf.runtime.DxDefinitions.*;
import static me.bechberger.ebpf.runtime.DynDefinitions.*;
import static me.bechberger.ebpf.runtime.DyneventDefinitions.*;
import static me.bechberger.ebpf.runtime.EafnosupportDefinitions.*;
import static me.bechberger.ebpf.runtime.EarlyDefinitions.*;
import static me.bechberger.ebpf.runtime.EbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.EcDefinitions.*;
import static me.bechberger.ebpf.runtime.EccDefinitions.*;
import static me.bechberger.ebpf.runtime.EcryptfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EdacDefinitions.*;
import static me.bechberger.ebpf.runtime.EddDefinitions.*;
import static me.bechberger.ebpf.runtime.EdidDefinitions.*;
import static me.bechberger.ebpf.runtime.EfiDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EhciDefinitions.*;
import static me.bechberger.ebpf.runtime.ElantsDefinitions.*;
import static me.bechberger.ebpf.runtime.ElevatorDefinitions.*;
import static me.bechberger.ebpf.runtime.ElfDefinitions.*;
import static me.bechberger.ebpf.runtime.ElvDefinitions.*;
import static me.bechberger.ebpf.runtime.EmDefinitions.*;
import static me.bechberger.ebpf.runtime.EmitDefinitions.*;
import static me.bechberger.ebpf.runtime.EnableDefinitions.*;
import static me.bechberger.ebpf.runtime.EndDefinitions.*;
import static me.bechberger.ebpf.runtime.EnqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.EpDefinitions.*;
import static me.bechberger.ebpf.runtime.EprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.ErstDefinitions.*;
import static me.bechberger.ebpf.runtime.EspintcpDefinitions.*;
import static me.bechberger.ebpf.runtime.EthDefinitions.*;
import static me.bechberger.ebpf.runtime.EthnlDefinitions.*;
import static me.bechberger.ebpf.runtime.EthtoolDefinitions.*;
import static me.bechberger.ebpf.runtime.EvdevDefinitions.*;
import static me.bechberger.ebpf.runtime.EventDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfdDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EvmDefinitions.*;
import static me.bechberger.ebpf.runtime.EvtchnDefinitions.*;
import static me.bechberger.ebpf.runtime.ExcDefinitions.*;
import static me.bechberger.ebpf.runtime.ExecmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ExitDefinitions.*;
import static me.bechberger.ebpf.runtime.Ext4Definitions.*;
import static me.bechberger.ebpf.runtime.ExtconDefinitions.*;
import static me.bechberger.ebpf.runtime.FDefinitions.*;
import static me.bechberger.ebpf.runtime.FanotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FatDefinitions.*;
import static me.bechberger.ebpf.runtime.FaultDefinitions.*;
import static me.bechberger.ebpf.runtime.FauxDefinitions.*;
import static me.bechberger.ebpf.runtime.FbDefinitions.*;
import static me.bechberger.ebpf.runtime.FbconDefinitions.*;
import static me.bechberger.ebpf.runtime.FdtDefinitions.*;
import static me.bechberger.ebpf.runtime.FfDefinitions.*;
import static me.bechberger.ebpf.runtime.FgraphDefinitions.*;
import static me.bechberger.ebpf.runtime.Fib4Definitions.*;
import static me.bechberger.ebpf.runtime.Fib6Definitions.*;
import static me.bechberger.ebpf.runtime.FibDefinitions.*;
import static me.bechberger.ebpf.runtime.FifoDefinitions.*;
import static me.bechberger.ebpf.runtime.FileDefinitions.*;
import static me.bechberger.ebpf.runtime.FilemapDefinitions.*;
import static me.bechberger.ebpf.runtime.FilenameDefinitions.*;
import static me.bechberger.ebpf.runtime.FillDefinitions.*;
import static me.bechberger.ebpf.runtime.FilterDefinitions.*;
import static me.bechberger.ebpf.runtime.FindDefinitions.*;
import static me.bechberger.ebpf.runtime.FinishDefinitions.*;
import static me.bechberger.ebpf.runtime.FirmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.FixedDefinitions.*;
import static me.bechberger.ebpf.runtime.FixupDefinitions.*;
import static me.bechberger.ebpf.runtime.FlowDefinitions.*;
import static me.bechberger.ebpf.runtime.FlushDefinitions.*;
import static me.bechberger.ebpf.runtime.FnDefinitions.*;
import static me.bechberger.ebpf.runtime.FolioDefinitions.*;
import static me.bechberger.ebpf.runtime.FollowDefinitions.*;
import static me.bechberger.ebpf.runtime.FopsDefinitions.*;
import static me.bechberger.ebpf.runtime.ForDefinitions.*;
import static me.bechberger.ebpf.runtime.ForceDefinitions.*;
import static me.bechberger.ebpf.runtime.FprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.FpuDefinitions.*;
import static me.bechberger.ebpf.runtime.FredDefinitions.*;
import static me.bechberger.ebpf.runtime.FreeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezerDefinitions.*;
import static me.bechberger.ebpf.runtime.FreqDefinitions.*;
import static me.bechberger.ebpf.runtime.FromDefinitions.*;
import static me.bechberger.ebpf.runtime.FsDefinitions.*;
import static me.bechberger.ebpf.runtime.FscryptDefinitions.*;
import static me.bechberger.ebpf.runtime.FseDefinitions.*;
import static me.bechberger.ebpf.runtime.FsnotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FsverityDefinitions.*;
import static me.bechberger.ebpf.runtime.FtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.FullDefinitions.*;
import static me.bechberger.ebpf.runtime.FunctionDefinitions.*;
import static me.bechberger.ebpf.runtime.FuseDefinitions.*;
import static me.bechberger.ebpf.runtime.FutexDefinitions.*;
import static me.bechberger.ebpf.runtime.FwDefinitions.*;
import static me.bechberger.ebpf.runtime.FwnodeDefinitions.*;
import static me.bechberger.ebpf.runtime.GartDefinitions.*;
import static me.bechberger.ebpf.runtime.GcmDefinitions.*;
import static me.bechberger.ebpf.runtime.GenDefinitions.*;
import static me.bechberger.ebpf.runtime.GenericDefinitions.*;
import static me.bechberger.ebpf.runtime.GenlDefinitions.*;
import static me.bechberger.ebpf.runtime.GenpdDefinitions.*;
import static me.bechberger.ebpf.runtime.GenphyDefinitions.*;
import static me.bechberger.ebpf.runtime.GetDefinitions.*;
import static me.bechberger.ebpf.runtime.GhesDefinitions.*;
import static me.bechberger.ebpf.runtime.GnetDefinitions.*;
import static me.bechberger.ebpf.runtime.GnttabDefinitions.*;
import static me.bechberger.ebpf.runtime.GpioDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiochipDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiodDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiolibDefinitions.*;
import static me.bechberger.ebpf.runtime.GroDefinitions.*;
import static me.bechberger.ebpf.runtime.GroupDefinitions.*;
import static me.bechberger.ebpf.runtime.GupDefinitions.*;
import static me.bechberger.ebpf.runtime.HandleDefinitions.*;
import static me.bechberger.ebpf.runtime.HandshakeDefinitions.*;
import static me.bechberger.ebpf.runtime.HasDefinitions.*;
import static me.bechberger.ebpf.runtime.HashDefinitions.*;
import static me.bechberger.ebpf.runtime.HcdDefinitions.*;
import static me.bechberger.ebpf.runtime.HctxDefinitions.*;
import static me.bechberger.ebpf.runtime.HdmiDefinitions.*;
import static me.bechberger.ebpf.runtime.HfiDefinitions.*;
import static me.bechberger.ebpf.runtime.HidDefinitions.*;
import static me.bechberger.ebpf.runtime.HistDefinitions.*;
import static me.bechberger.ebpf.runtime.HmacDefinitions.*;
import static me.bechberger.ebpf.runtime.HmatDefinitions.*;
import static me.bechberger.ebpf.runtime.HmmDefinitions.*;
import static me.bechberger.ebpf.runtime.HookDefinitions.*;
import static me.bechberger.ebpf.runtime.HpetDefinitions.*;
import static me.bechberger.ebpf.runtime.HrtimerDefinitions.*;
import static me.bechberger.ebpf.runtime.HsuDefinitions.*;
import static me.bechberger.ebpf.runtime.HswepDefinitions.*;
import static me.bechberger.ebpf.runtime.HtabDefinitions.*;
import static me.bechberger.ebpf.runtime.HteDefinitions.*;
import static me.bechberger.ebpf.runtime.HubDefinitions.*;
import static me.bechberger.ebpf.runtime.HufDefinitions.*;
import static me.bechberger.ebpf.runtime.HugepageDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbfsDefinitions.*;
import static me.bechberger.ebpf.runtime.HvDefinitions.*;
import static me.bechberger.ebpf.runtime.HvcDefinitions.*;
import static me.bechberger.ebpf.runtime.HwDefinitions.*;
import static me.bechberger.ebpf.runtime.HwlatDefinitions.*;
import static me.bechberger.ebpf.runtime.HwmonDefinitions.*;
import static me.bechberger.ebpf.runtime.HybridDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervisorDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cdevDefinitions.*;
import static me.bechberger.ebpf.runtime.I8042Definitions.*;
import static me.bechberger.ebpf.runtime.Ia32Definitions.*;
import static me.bechberger.ebpf.runtime.IbDefinitions.*;
import static me.bechberger.ebpf.runtime.IccDefinitions.*;
import static me.bechberger.ebpf.runtime.IcmpDefinitions.*;
import static me.bechberger.ebpf.runtime.Icmpv6Definitions.*;
import static me.bechberger.ebpf.runtime.IcxDefinitions.*;
import static me.bechberger.ebpf.runtime.IdleDefinitions.*;
import static me.bechberger.ebpf.runtime.IdrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ieee80211Definitions.*;
import static me.bechberger.ebpf.runtime.IflaDefinitions.*;
import static me.bechberger.ebpf.runtime.Igmp6Definitions.*;
import static me.bechberger.ebpf.runtime.IgmpDefinitions.*;
import static me.bechberger.ebpf.runtime.ImaDefinitions.*;
import static me.bechberger.ebpf.runtime.ImsttfbDefinitions.*;
import static me.bechberger.ebpf.runtime.In6Definitions.*;
import static me.bechberger.ebpf.runtime.InDefinitions.*;
import static me.bechberger.ebpf.runtime.IncDefinitions.*;
import static me.bechberger.ebpf.runtime.Inet6Definitions.*;
import static me.bechberger.ebpf.runtime.InetDefinitions.*;
import static me.bechberger.ebpf.runtime.InitDefinitions.*;
import static me.bechberger.ebpf.runtime.InodeDefinitions.*;
import static me.bechberger.ebpf.runtime.InotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.InputDefinitions.*;
import static me.bechberger.ebpf.runtime.InsertDefinitions.*;
import static me.bechberger.ebpf.runtime.InsnDefinitions.*;
import static me.bechberger.ebpf.runtime.IntDefinitions.*;
import static me.bechberger.ebpf.runtime.IntegrityDefinitions.*;
import static me.bechberger.ebpf.runtime.IntelDefinitions.*;
import static me.bechberger.ebpf.runtime.IntervalDefinitions.*;
import static me.bechberger.ebpf.runtime.InvalidateDefinitions.*;
import static me.bechberger.ebpf.runtime.IoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ioam6Definitions.*;
import static me.bechberger.ebpf.runtime.IoapicDefinitions.*;
import static me.bechberger.ebpf.runtime.IocDefinitions.*;
import static me.bechberger.ebpf.runtime.IocgDefinitions.*;
import static me.bechberger.ebpf.runtime.IoctlDefinitions.*;
import static me.bechberger.ebpf.runtime.IomapDefinitions.*;
import static me.bechberger.ebpf.runtime.IommuDefinitions.*;
import static me.bechberger.ebpf.runtime.IommufdDefinitions.*;
import static me.bechberger.ebpf.runtime.IopfDefinitions.*;
import static me.bechberger.ebpf.runtime.IoremapDefinitions.*;
import static me.bechberger.ebpf.runtime.IosfDefinitions.*;
import static me.bechberger.ebpf.runtime.IovDefinitions.*;
import static me.bechberger.ebpf.runtime.IovaDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip4Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6addrlblDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip6mrDefinitions.*;
import static me.bechberger.ebpf.runtime.IpDefinitions.*;
import static me.bechberger.ebpf.runtime.IpcDefinitions.*;
import static me.bechberger.ebpf.runtime.IpeDefinitions.*;
import static me.bechberger.ebpf.runtime.IpmrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ipv4Definitions.*;
import static me.bechberger.ebpf.runtime.Ipv6Definitions.*;
import static me.bechberger.ebpf.runtime.IrqDefinitions.*;
import static me.bechberger.ebpf.runtime.IrteDefinitions.*;
import static me.bechberger.ebpf.runtime.IsDefinitions.*;
import static me.bechberger.ebpf.runtime.IsaDefinitions.*;
import static me.bechberger.ebpf.runtime.IsolateDefinitions.*;
import static me.bechberger.ebpf.runtime.IterDefinitions.*;
import static me.bechberger.ebpf.runtime.IvbepDefinitions.*;
import static me.bechberger.ebpf.runtime.IwDefinitions.*;
import static me.bechberger.ebpf.runtime.JailhouseDefinitions.*;
import static me.bechberger.ebpf.runtime.Jbd2Definitions.*;
import static me.bechberger.ebpf.runtime.JentDefinitions.*;
import static me.bechberger.ebpf.runtime.JournalDefinitions.*;
import static me.bechberger.ebpf.runtime.JumpDefinitions.*;
import static me.bechberger.ebpf.runtime.KDefinitions.*;
import static me.bechberger.ebpf.runtime.KallsymsDefinitions.*;
import static me.bechberger.ebpf.runtime.KbdDefinitions.*;
import static me.bechberger.ebpf.runtime.KdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KernDefinitions.*;
import static me.bechberger.ebpf.runtime.KernelDefinitions.*;
import static me.bechberger.ebpf.runtime.KernfsDefinitions.*;
import static me.bechberger.ebpf.runtime.KexecDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyctlDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyringDefinitions.*;
import static me.bechberger.ebpf.runtime.KfenceDefinitions.*;
import static me.bechberger.ebpf.runtime.KfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.KfreeDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbocDefinitions.*;
import static me.bechberger.ebpf.runtime.KhoDefinitions.*;
import static me.bechberger.ebpf.runtime.KillDefinitions.*;
import static me.bechberger.ebpf.runtime.KimageDefinitions.*;
import static me.bechberger.ebpf.runtime.KlistDefinitions.*;
import static me.bechberger.ebpf.runtime.KlpDefinitions.*;
import static me.bechberger.ebpf.runtime.KmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.KmemDefinitions.*;
import static me.bechberger.ebpf.runtime.KmsgDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjectDefinitions.*;
import static me.bechberger.ebpf.runtime.KprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.KsmDefinitions.*;
import static me.bechberger.ebpf.runtime.KsysDefinitions.*;
import static me.bechberger.ebpf.runtime.KthreadDefinitions.*;
import static me.bechberger.ebpf.runtime.KtimeDefinitions.*;
import static me.bechberger.ebpf.runtime.KvmDefinitions.*;
import static me.bechberger.ebpf.runtime.L3mdevDefinitions.*;
import static me.bechberger.ebpf.runtime.LabelDefinitions.*;
import static me.bechberger.ebpf.runtime.LandlockDefinitions.*;
import static me.bechberger.ebpf.runtime.LapicDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.LedDefinitions.*;
import static me.bechberger.ebpf.runtime.LedtrigDefinitions.*;
import static me.bechberger.ebpf.runtime.LegacyDefinitions.*;
import static me.bechberger.ebpf.runtime.LinearDefinitions.*;
import static me.bechberger.ebpf.runtime.LineeventDefinitions.*;
import static me.bechberger.ebpf.runtime.LinereqDefinitions.*;
import static me.bechberger.ebpf.runtime.LinkDefinitions.*;
import static me.bechberger.ebpf.runtime.LinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.ListDefinitions.*;
import static me.bechberger.ebpf.runtime.LoadDefinitions.*;
import static me.bechberger.ebpf.runtime.LocalDefinitions.*;
import static me.bechberger.ebpf.runtime.LockDefinitions.*;
import static me.bechberger.ebpf.runtime.LocksDefinitions.*;
import static me.bechberger.ebpf.runtime.LockupDefinitions.*;
import static me.bechberger.ebpf.runtime.LogDefinitions.*;
import static me.bechberger.ebpf.runtime.LookupDefinitions.*;
import static me.bechberger.ebpf.runtime.LoopDefinitions.*;
import static me.bechberger.ebpf.runtime.Lp8788Definitions.*;
import static me.bechberger.ebpf.runtime.LpssDefinitions.*;
import static me.bechberger.ebpf.runtime.LruDefinitions.*;
import static me.bechberger.ebpf.runtime.LskcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.LsmDefinitions.*;
import static me.bechberger.ebpf.runtime.LwtunnelDefinitions.*;
import static me.bechberger.ebpf.runtime.Lz4Definitions.*;
import static me.bechberger.ebpf.runtime.MachineDefinitions.*;
import static me.bechberger.ebpf.runtime.MacsecDefinitions.*;
import static me.bechberger.ebpf.runtime.MadviseDefinitions.*;
import static me.bechberger.ebpf.runtime.MakeDefinitions.*;
import static me.bechberger.ebpf.runtime.MapDefinitions.*;
import static me.bechberger.ebpf.runtime.MapleDefinitions.*;
import static me.bechberger.ebpf.runtime.MarkDefinitions.*;
import static me.bechberger.ebpf.runtime.MasDefinitions.*;
import static me.bechberger.ebpf.runtime.MatchDefinitions.*;
import static me.bechberger.ebpf.runtime.Max310xDefinitions.*;
import static me.bechberger.ebpf.runtime.Max77693Definitions.*;
import static me.bechberger.ebpf.runtime.Max8925Definitions.*;
import static me.bechberger.ebpf.runtime.Max8997Definitions.*;
import static me.bechberger.ebpf.runtime.Max8998Definitions.*;
import static me.bechberger.ebpf.runtime.MaxDefinitions.*;
import static me.bechberger.ebpf.runtime.MayDefinitions.*;
import static me.bechberger.ebpf.runtime.MaybeDefinitions.*;
import static me.bechberger.ebpf.runtime.MbDefinitions.*;
import static me.bechberger.ebpf.runtime.MbmDefinitions.*;
import static me.bechberger.ebpf.runtime.MboxDefinitions.*;
import static me.bechberger.ebpf.runtime.MceDefinitions.*;
import static me.bechberger.ebpf.runtime.McheckDefinitions.*;
import static me.bechberger.ebpf.runtime.MciDefinitions.*;
import static me.bechberger.ebpf.runtime.MctpDefinitions.*;
import static me.bechberger.ebpf.runtime.MctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.MdDefinitions.*;
import static me.bechberger.ebpf.runtime.MddevDefinitions.*;
import static me.bechberger.ebpf.runtime.MdioDefinitions.*;
import static me.bechberger.ebpf.runtime.MdiobusDefinitions.*;
import static me.bechberger.ebpf.runtime.MemDefinitions.*;
import static me.bechberger.ebpf.runtime.MemblockDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcgDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcpyDefinitions.*;
import static me.bechberger.ebpf.runtime.MemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MemoryDefinitions.*;
import static me.bechberger.ebpf.runtime.MempoolDefinitions.*;
import static me.bechberger.ebpf.runtime.MemtypeDefinitions.*;
import static me.bechberger.ebpf.runtime.MigrateDefinitions.*;
import static me.bechberger.ebpf.runtime.MinDefinitions.*;
import static me.bechberger.ebpf.runtime.MipiDefinitions.*;
import static me.bechberger.ebpf.runtime.MiscDefinitions.*;
import static me.bechberger.ebpf.runtime.MldDefinitions.*;
import static me.bechberger.ebpf.runtime.MlsDefinitions.*;
import static me.bechberger.ebpf.runtime.MmDefinitions.*;
import static me.bechberger.ebpf.runtime.MmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MmcDefinitions.*;
import static me.bechberger.ebpf.runtime.MmioDefinitions.*;
import static me.bechberger.ebpf.runtime.MmuDefinitions.*;
import static me.bechberger.ebpf.runtime.MntDefinitions.*;
import static me.bechberger.ebpf.runtime.ModDefinitions.*;
import static me.bechberger.ebpf.runtime.ModuleDefinitions.*;
import static me.bechberger.ebpf.runtime.MountDefinitions.*;
import static me.bechberger.ebpf.runtime.MousedevDefinitions.*;
import static me.bechberger.ebpf.runtime.MoveDefinitions.*;
import static me.bechberger.ebpf.runtime.MpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpageDefinitions.*;
import static me.bechberger.ebpf.runtime.MpiDefinitions.*;
import static me.bechberger.ebpf.runtime.MpihelpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpolDefinitions.*;
import static me.bechberger.ebpf.runtime.MptcpDefinitions.*;
import static me.bechberger.ebpf.runtime.MqDefinitions.*;
import static me.bechberger.ebpf.runtime.MqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.MrDefinitions.*;
import static me.bechberger.ebpf.runtime.MsgDefinitions.*;
import static me.bechberger.ebpf.runtime.MsiDefinitions.*;
import static me.bechberger.ebpf.runtime.MsrDefinitions.*;
import static me.bechberger.ebpf.runtime.MtDefinitions.*;
import static me.bechberger.ebpf.runtime.MtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.MtrrDefinitions.*;
import static me.bechberger.ebpf.runtime.MutexDefinitions.*;
import static me.bechberger.ebpf.runtime.NDefinitions.*;
import static me.bechberger.ebpf.runtime.NapiDefinitions.*;
import static me.bechberger.ebpf.runtime.NativeDefinitions.*;
import static me.bechberger.ebpf.runtime.NbconDefinitions.*;
import static me.bechberger.ebpf.runtime.NcsiDefinitions.*;
import static me.bechberger.ebpf.runtime.NdDefinitions.*;
import static me.bechberger.ebpf.runtime.NdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.NeighDefinitions.*;
import static me.bechberger.ebpf.runtime.NetDefinitions.*;
import static me.bechberger.ebpf.runtime.NetdevDefinitions.*;
import static me.bechberger.ebpf.runtime.NetifDefinitions.*;
import static me.bechberger.ebpf.runtime.NetkitDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlblDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.NetnsDefinitions.*;
import static me.bechberger.ebpf.runtime.NetpollDefinitions.*;
import static me.bechberger.ebpf.runtime.NewDefinitions.*;
import static me.bechberger.ebpf.runtime.NextDefinitions.*;
import static me.bechberger.ebpf.runtime.NexthopDefinitions.*;
import static me.bechberger.ebpf.runtime.NfDefinitions.*;
import static me.bechberger.ebpf.runtime.Nfs4Definitions.*;
import static me.bechberger.ebpf.runtime.NfsDefinitions.*;
import static me.bechberger.ebpf.runtime.NhDefinitions.*;
import static me.bechberger.ebpf.runtime.NhmexDefinitions.*;
import static me.bechberger.ebpf.runtime.Nl80211Definitions.*;
import static me.bechberger.ebpf.runtime.NlaDefinitions.*;
import static me.bechberger.ebpf.runtime.NmiDefinitions.*;
import static me.bechberger.ebpf.runtime.NoDefinitions.*;
import static me.bechberger.ebpf.runtime.NodeDefinitions.*;
import static me.bechberger.ebpf.runtime.NoopDefinitions.*;
import static me.bechberger.ebpf.runtime.NotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.NrDefinitions.*;
import static me.bechberger.ebpf.runtime.NsDefinitions.*;
import static me.bechberger.ebpf.runtime.NullDefinitions.*;
import static me.bechberger.ebpf.runtime.NumaDefinitions.*;
import static me.bechberger.ebpf.runtime.NumachipDefinitions.*;
import static me.bechberger.ebpf.runtime.NvdimmDefinitions.*;
import static me.bechberger.ebpf.runtime.NvmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ObjDefinitions.*;
import static me.bechberger.ebpf.runtime.OctepDefinitions.*;
import static me.bechberger.ebpf.runtime.OdDefinitions.*;
import static me.bechberger.ebpf.runtime.OfDefinitions.*;
import static me.bechberger.ebpf.runtime.OhciDefinitions.*;
import static me.bechberger.ebpf.runtime.OldDefinitions.*;
import static me.bechberger.ebpf.runtime.OomDefinitions.*;
import static me.bechberger.ebpf.runtime.OpalDefinitions.*;
import static me.bechberger.ebpf.runtime.OpenDefinitions.*;
import static me.bechberger.ebpf.runtime.OppDefinitions.*;
import static me.bechberger.ebpf.runtime.OsnoiseDefinitions.*;
import static me.bechberger.ebpf.runtime.P4Definitions.*;
import static me.bechberger.ebpf.runtime.PacketDefinitions.*;
import static me.bechberger.ebpf.runtime.PadataDefinitions.*;
import static me.bechberger.ebpf.runtime.PageDefinitions.*;
import static me.bechberger.ebpf.runtime.PagemapDefinitions.*;
import static me.bechberger.ebpf.runtime.PagesDefinitions.*;
import static me.bechberger.ebpf.runtime.PalmasDefinitions.*;
import static me.bechberger.ebpf.runtime.PanelDefinitions.*;
import static me.bechberger.ebpf.runtime.ParamDefinitions.*;
import static me.bechberger.ebpf.runtime.ParseDefinitions.*;
import static me.bechberger.ebpf.runtime.PartDefinitions.*;
import static me.bechberger.ebpf.runtime.PathDefinitions.*;
import static me.bechberger.ebpf.runtime.PcapDefinitions.*;
import static me.bechberger.ebpf.runtime.PccDefinitions.*;
import static me.bechberger.ebpf.runtime.PciDefinitions.*;
import static me.bechberger.ebpf.runtime.PcibiosDefinitions.*;
import static me.bechberger.ebpf.runtime.PcieDefinitions.*;
import static me.bechberger.ebpf.runtime.PciehpDefinitions.*;
import static me.bechberger.ebpf.runtime.PcimDefinitions.*;
import static me.bechberger.ebpf.runtime.PcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PercpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PerfDefinitions.*;
import static me.bechberger.ebpf.runtime.PfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.PfnDefinitions.*;
import static me.bechberger.ebpf.runtime.PhyDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysdevDefinitions.*;
import static me.bechberger.ebpf.runtime.PickDefinitions.*;
import static me.bechberger.ebpf.runtime.PidDefinitions.*;
import static me.bechberger.ebpf.runtime.PidfsDefinitions.*;
import static me.bechberger.ebpf.runtime.PidsDefinitions.*;
import static me.bechberger.ebpf.runtime.PiixDefinitions.*;
import static me.bechberger.ebpf.runtime.PinDefinitions.*;
import static me.bechberger.ebpf.runtime.PinconfDefinitions.*;
import static me.bechberger.ebpf.runtime.PinctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.PingDefinitions.*;
import static me.bechberger.ebpf.runtime.PinmuxDefinitions.*;
import static me.bechberger.ebpf.runtime.PipeDefinitions.*;
import static me.bechberger.ebpf.runtime.PirqDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs1padDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs7Definitions.*;
import static me.bechberger.ebpf.runtime.PlatformDefinitions.*;
import static me.bechberger.ebpf.runtime.PldmfwDefinitions.*;
import static me.bechberger.ebpf.runtime.Pm860xDefinitions.*;
import static me.bechberger.ebpf.runtime.PmDefinitions.*;
import static me.bechberger.ebpf.runtime.PmcDefinitions.*;
import static me.bechberger.ebpf.runtime.PmdDefinitions.*;
import static me.bechberger.ebpf.runtime.PmuDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpacpiDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicyDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicydbDefinitions.*;
import static me.bechberger.ebpf.runtime.PollDefinitions.*;
import static me.bechberger.ebpf.runtime.Poly1305Definitions.*;
import static me.bechberger.ebpf.runtime.PopulateDefinitions.*;
import static me.bechberger.ebpf.runtime.PortDefinitions.*;
import static me.bechberger.ebpf.runtime.PosixDefinitions.*;
import static me.bechberger.ebpf.runtime.PowerDefinitions.*;
import static me.bechberger.ebpf.runtime.PowercapDefinitions.*;
import static me.bechberger.ebpf.runtime.PppDefinitions.*;
import static me.bechberger.ebpf.runtime.PpsDefinitions.*;
import static me.bechberger.ebpf.runtime.PrDefinitions.*;
import static me.bechberger.ebpf.runtime.PrbDefinitions.*;
import static me.bechberger.ebpf.runtime.PreemptDefinitions.*;
import static me.bechberger.ebpf.runtime.PrepareDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintkDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbeDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbestubDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcessDefinitions.*;
import static me.bechberger.ebpf.runtime.ProfileDefinitions.*;
import static me.bechberger.ebpf.runtime.ProgDefinitions.*;
import static me.bechberger.ebpf.runtime.PropagateDefinitions.*;
import static me.bechberger.ebpf.runtime.ProtoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ps2Definitions.*;
import static me.bechberger.ebpf.runtime.PseDefinitions.*;
import static me.bechberger.ebpf.runtime.PseudoDefinitions.*;
import static me.bechberger.ebpf.runtime.PsiDefinitions.*;
import static me.bechberger.ebpf.runtime.PskbDefinitions.*;
import static me.bechberger.ebpf.runtime.PstoreDefinitions.*;
import static me.bechberger.ebpf.runtime.PtDefinitions.*;
import static me.bechberger.ebpf.runtime.PtdumpDefinitions.*;
import static me.bechberger.ebpf.runtime.PteDefinitions.*;
import static me.bechberger.ebpf.runtime.PtiDefinitions.*;
import static me.bechberger.ebpf.runtime.PtpDefinitions.*;
import static me.bechberger.ebpf.runtime.PtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.PtyDefinitions.*;
import static me.bechberger.ebpf.runtime.PushDefinitions.*;
import static me.bechberger.ebpf.runtime.PutDefinitions.*;
import static me.bechberger.ebpf.runtime.PvDefinitions.*;
import static me.bechberger.ebpf.runtime.PvclockDefinitions.*;
import static me.bechberger.ebpf.runtime.PwmDefinitions.*;
import static me.bechberger.ebpf.runtime.QdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.QhDefinitions.*;
import static me.bechberger.ebpf.runtime.QiDefinitions.*;
import static me.bechberger.ebpf.runtime.QueueDefinitions.*;
import static me.bechberger.ebpf.runtime.QuirkDefinitions.*;
import static me.bechberger.ebpf.runtime.QuotaDefinitions.*;
import static me.bechberger.ebpf.runtime.RadixDefinitions.*;
import static me.bechberger.ebpf.runtime.RamfsDefinitions.*;
import static me.bechberger.ebpf.runtime.RandomDefinitions.*;
import static me.bechberger.ebpf.runtime.RangeDefinitions.*;
import static me.bechberger.ebpf.runtime.Raw6Definitions.*;
import static me.bechberger.ebpf.runtime.RawDefinitions.*;
import static me.bechberger.ebpf.runtime.Rawv6Definitions.*;
import static me.bechberger.ebpf.runtime.RbDefinitions.*;
import static me.bechberger.ebpf.runtime.Rc5t583Definitions.*;
import static me.bechberger.ebpf.runtime.RcuDefinitions.*;
import static me.bechberger.ebpf.runtime.RdevDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmacgDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ReadDefinitions.*;
import static me.bechberger.ebpf.runtime.ReclaimDefinitions.*;
import static me.bechberger.ebpf.runtime.RegDefinitions.*;
import static me.bechberger.ebpf.runtime.RegcacheDefinitions.*;
import static me.bechberger.ebpf.runtime.RegisterDefinitions.*;
import static me.bechberger.ebpf.runtime.RegmapDefinitions.*;
import static me.bechberger.ebpf.runtime.RegulatorDefinitions.*;
import static me.bechberger.ebpf.runtime.RelayDefinitions.*;
import static me.bechberger.ebpf.runtime.ReleaseDefinitions.*;
import static me.bechberger.ebpf.runtime.RemapDefinitions.*;
import static me.bechberger.ebpf.runtime.RemoveDefinitions.*;
import static me.bechberger.ebpf.runtime.ReplaceDefinitions.*;
import static me.bechberger.ebpf.runtime.ReportDefinitions.*;
import static me.bechberger.ebpf.runtime.RequestDefinitions.*;
import static me.bechberger.ebpf.runtime.ResctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.ReserveDefinitions.*;
import static me.bechberger.ebpf.runtime.ResetDefinitions.*;
import static me.bechberger.ebpf.runtime.ResourceDefinitions.*;
import static me.bechberger.ebpf.runtime.RestoreDefinitions.*;
import static me.bechberger.ebpf.runtime.RestrictDefinitions.*;
import static me.bechberger.ebpf.runtime.ResumeDefinitions.*;
import static me.bechberger.ebpf.runtime.RethookDefinitions.*;
import static me.bechberger.ebpf.runtime.ReuseportDefinitions.*;
import static me.bechberger.ebpf.runtime.RfkillDefinitions.*;
import static me.bechberger.ebpf.runtime.RhashtableDefinitions.*;
import static me.bechberger.ebpf.runtime.RingDefinitions.*;
import static me.bechberger.ebpf.runtime.RingbufDefinitions.*;
import static me.bechberger.ebpf.runtime.RioDefinitions.*;
import static me.bechberger.ebpf.runtime.RngDefinitions.*;
import static me.bechberger.ebpf.runtime.RoleDefinitions.*;
import static me.bechberger.ebpf.runtime.RpcDefinitions.*;
import static me.bechberger.ebpf.runtime.RpmDefinitions.*;
import static me.bechberger.ebpf.runtime.RprocDefinitions.*;
import static me.bechberger.ebpf.runtime.RqDefinitions.*;
import static me.bechberger.ebpf.runtime.RsaDefinitions.*;
import static me.bechberger.ebpf.runtime.RsassaDefinitions.*;
import static me.bechberger.ebpf.runtime.RseqDefinitions.*;
import static me.bechberger.ebpf.runtime.RssDefinitions.*;
import static me.bechberger.ebpf.runtime.Rt6Definitions.*;
import static me.bechberger.ebpf.runtime.RtDefinitions.*;
import static me.bechberger.ebpf.runtime.RtcDefinitions.*;
import static me.bechberger.ebpf.runtime.RtmDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnlDefinitions.*;
import static me.bechberger.ebpf.runtime.RunDefinitions.*;
import static me.bechberger.ebpf.runtime.RustDefinitions.*;
import static me.bechberger.ebpf.runtime.RvDefinitions.*;
import static me.bechberger.ebpf.runtime.RxDefinitions.*;
import static me.bechberger.ebpf.runtime.SDefinitions.*;
import static me.bechberger.ebpf.runtime.SataDefinitions.*;
import static me.bechberger.ebpf.runtime.SaveDefinitions.*;
import static me.bechberger.ebpf.runtime.SavedDefinitions.*;
import static me.bechberger.ebpf.runtime.SbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.ScanDefinitions.*;
import static me.bechberger.ebpf.runtime.SccnxpDefinitions.*;
import static me.bechberger.ebpf.runtime.SchedDefinitions.*;
import static me.bechberger.ebpf.runtime.ScheduleDefinitions.*;
import static me.bechberger.ebpf.runtime.ScmDefinitions.*;
import static me.bechberger.ebpf.runtime.SctpDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.SdDefinitions.*;
import static me.bechberger.ebpf.runtime.SdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SdioDefinitions.*;
import static me.bechberger.ebpf.runtime.SeccompDefinitions.*;
import static me.bechberger.ebpf.runtime.SecurityDefinitions.*;
import static me.bechberger.ebpf.runtime.Seg6Definitions.*;
import static me.bechberger.ebpf.runtime.SelDefinitions.*;
import static me.bechberger.ebpf.runtime.SelectDefinitions.*;
import static me.bechberger.ebpf.runtime.SelinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.SendDefinitions.*;
import static me.bechberger.ebpf.runtime.SeqDefinitions.*;
import static me.bechberger.ebpf.runtime.SerdevDefinitions.*;
import static me.bechberger.ebpf.runtime.Serial8250Definitions.*;
import static me.bechberger.ebpf.runtime.SerialDefinitions.*;
import static me.bechberger.ebpf.runtime.SerioDefinitions.*;
import static me.bechberger.ebpf.runtime.SetDefinitions.*;
import static me.bechberger.ebpf.runtime.SetupDefinitions.*;
import static me.bechberger.ebpf.runtime.SevDefinitions.*;
import static me.bechberger.ebpf.runtime.SfpDefinitions.*;
import static me.bechberger.ebpf.runtime.SgDefinitions.*;
import static me.bechberger.ebpf.runtime.SgxDefinitions.*;
import static me.bechberger.ebpf.runtime.Sha1Definitions.*;
import static me.bechberger.ebpf.runtime.Sha256Definitions.*;
import static me.bechberger.ebpf.runtime.Sha512Definitions.*;
import static me.bechberger.ebpf.runtime.ShashDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ShouldDefinitions.*;
import static me.bechberger.ebpf.runtime.ShowDefinitions.*;
import static me.bechberger.ebpf.runtime.ShpchpDefinitions.*;
import static me.bechberger.ebpf.runtime.ShrinkDefinitions.*;
import static me.bechberger.ebpf.runtime.SidtabDefinitions.*;
import static me.bechberger.ebpf.runtime.SimpleDefinitions.*;
import static me.bechberger.ebpf.runtime.SingleDefinitions.*;
import static me.bechberger.ebpf.runtime.SisDefinitions.*;
import static me.bechberger.ebpf.runtime.SkDefinitions.*;
import static me.bechberger.ebpf.runtime.SkbDefinitions.*;
import static me.bechberger.ebpf.runtime.SkcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.SkxDefinitions.*;
import static me.bechberger.ebpf.runtime.SlabDefinitions.*;
import static me.bechberger.ebpf.runtime.SmackDefinitions.*;
import static me.bechberger.ebpf.runtime.SmeDefinitions.*;
import static me.bechberger.ebpf.runtime.SmkDefinitions.*;
import static me.bechberger.ebpf.runtime.SmpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnapshotDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbepDefinitions.*;
import static me.bechberger.ebpf.runtime.SnpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnrDefinitions.*;
import static me.bechberger.ebpf.runtime.SocDefinitions.*;
import static me.bechberger.ebpf.runtime.SockDefinitions.*;
import static me.bechberger.ebpf.runtime.SoftwareDefinitions.*;
import static me.bechberger.ebpf.runtime.SparseDefinitions.*;
import static me.bechberger.ebpf.runtime.SpiDefinitions.*;
import static me.bechberger.ebpf.runtime.SpliceDefinitions.*;
import static me.bechberger.ebpf.runtime.SplitDefinitions.*;
import static me.bechberger.ebpf.runtime.SprDefinitions.*;
import static me.bechberger.ebpf.runtime.SquashfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SrDefinitions.*;
import static me.bechberger.ebpf.runtime.SramDefinitions.*;
import static me.bechberger.ebpf.runtime.SrcuDefinitions.*;
import static me.bechberger.ebpf.runtime.SriovDefinitions.*;
import static me.bechberger.ebpf.runtime.StackDefinitions.*;
import static me.bechberger.ebpf.runtime.StartDefinitions.*;
import static me.bechberger.ebpf.runtime.StatDefinitions.*;
import static me.bechberger.ebpf.runtime.StaticDefinitions.*;
import static me.bechberger.ebpf.runtime.StatsDefinitions.*;
import static me.bechberger.ebpf.runtime.StopDefinitions.*;
import static me.bechberger.ebpf.runtime.StoreDefinitions.*;
import static me.bechberger.ebpf.runtime.StripeDefinitions.*;
import static me.bechberger.ebpf.runtime.StrpDefinitions.*;
import static me.bechberger.ebpf.runtime.SubflowDefinitions.*;
import static me.bechberger.ebpf.runtime.SubmitDefinitions.*;
import static me.bechberger.ebpf.runtime.SugovDefinitions.*;
import static me.bechberger.ebpf.runtime.SuperDefinitions.*;
import static me.bechberger.ebpf.runtime.SuspendDefinitions.*;
import static me.bechberger.ebpf.runtime.SvcDefinitions.*;
import static me.bechberger.ebpf.runtime.SvsmDefinitions.*;
import static me.bechberger.ebpf.runtime.SwDefinitions.*;
import static me.bechberger.ebpf.runtime.SwapDefinitions.*;
import static me.bechberger.ebpf.runtime.SwiotlbDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SwsuspDefinitions.*;
import static me.bechberger.ebpf.runtime.Sx150xDefinitions.*;
import static me.bechberger.ebpf.runtime.SyncDefinitions.*;
import static me.bechberger.ebpf.runtime.SynchronizeDefinitions.*;
import static me.bechberger.ebpf.runtime.SynthDefinitions.*;
import static me.bechberger.ebpf.runtime.SysDefinitions.*;
import static me.bechberger.ebpf.runtime.SyscallDefinitions.*;
import static me.bechberger.ebpf.runtime.SysctlDefinitions.*;
import static me.bechberger.ebpf.runtime.SysfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SysrqDefinitions.*;
import static me.bechberger.ebpf.runtime.SystemDefinitions.*;
import static me.bechberger.ebpf.runtime.SysvecDefinitions.*;
import static me.bechberger.ebpf.runtime.TargetDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskletDefinitions.*;
import static me.bechberger.ebpf.runtime.TbootDefinitions.*;
import static me.bechberger.ebpf.runtime.TcDefinitions.*;
import static me.bechberger.ebpf.runtime.TcfDefinitions.*;
import static me.bechberger.ebpf.runtime.TcpDefinitions.*;
import static me.bechberger.ebpf.runtime.TcxDefinitions.*;
import static me.bechberger.ebpf.runtime.TdhDefinitions.*;
import static me.bechberger.ebpf.runtime.TdxDefinitions.*;
import static me.bechberger.ebpf.runtime.TestDefinitions.*;
import static me.bechberger.ebpf.runtime.TextDefinitions.*;
import static me.bechberger.ebpf.runtime.TgDefinitions.*;
import static me.bechberger.ebpf.runtime.ThermalDefinitions.*;
import static me.bechberger.ebpf.runtime.ThreadDefinitions.*;
import static me.bechberger.ebpf.runtime.ThrotlDefinitions.*;
import static me.bechberger.ebpf.runtime.TickDefinitions.*;
import static me.bechberger.ebpf.runtime.TimekeepingDefinitions.*;
import static me.bechberger.ebpf.runtime.TimensDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerfdDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerlatDefinitions.*;
import static me.bechberger.ebpf.runtime.TkDefinitions.*;
import static me.bechberger.ebpf.runtime.TlbDefinitions.*;
import static me.bechberger.ebpf.runtime.TlsDefinitions.*;
import static me.bechberger.ebpf.runtime.TmigrDefinitions.*;
import static me.bechberger.ebpf.runtime.TnumDefinitions.*;
import static me.bechberger.ebpf.runtime.ToDefinitions.*;
import static me.bechberger.ebpf.runtime.TomoyoDefinitions.*;
import static me.bechberger.ebpf.runtime.TopologyDefinitions.*;
import static me.bechberger.ebpf.runtime.TouchDefinitions.*;
import static me.bechberger.ebpf.runtime.TpacketDefinitions.*;
import static me.bechberger.ebpf.runtime.Tpm1Definitions.*;
import static me.bechberger.ebpf.runtime.Tpm2Definitions.*;
import static me.bechberger.ebpf.runtime.TpmDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps6586xDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps65910Definitions.*;
import static me.bechberger.ebpf.runtime.TraceDefinitions.*;
import static me.bechberger.ebpf.runtime.TracefsDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceiterDefinitions.*;
import static me.bechberger.ebpf.runtime.TracepointDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.TracerDefinitions.*;
import static me.bechberger.ebpf.runtime.TracingDefinitions.*;
import static me.bechberger.ebpf.runtime.TransportDefinitions.*;
import static me.bechberger.ebpf.runtime.TrieDefinitions.*;
import static me.bechberger.ebpf.runtime.TruncateDefinitions.*;
import static me.bechberger.ebpf.runtime.TrustedDefinitions.*;
import static me.bechberger.ebpf.runtime.TryDefinitions.*;
import static me.bechberger.ebpf.runtime.TscDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyportDefinitions.*;
import static me.bechberger.ebpf.runtime.TunDefinitions.*;
import static me.bechberger.ebpf.runtime.Twl4030Definitions.*;
import static me.bechberger.ebpf.runtime.Twl6040Definitions.*;
import static me.bechberger.ebpf.runtime.TwlDefinitions.*;
import static me.bechberger.ebpf.runtime.TxDefinitions.*;
import static me.bechberger.ebpf.runtime.TypeDefinitions.*;
import static me.bechberger.ebpf.runtime.UDefinitions.*;
import static me.bechberger.ebpf.runtime.UartDefinitions.*;
import static me.bechberger.ebpf.runtime.UbsanDefinitions.*;
import static me.bechberger.ebpf.runtime.Udp4Definitions.*;
import static me.bechberger.ebpf.runtime.Udp6Definitions.*;
import static me.bechberger.ebpf.runtime.UdpDefinitions.*;
import static me.bechberger.ebpf.runtime.Udpv6Definitions.*;
import static me.bechberger.ebpf.runtime.UhciDefinitions.*;
import static me.bechberger.ebpf.runtime.UinputDefinitions.*;
import static me.bechberger.ebpf.runtime.UncoreDefinitions.*;
import static me.bechberger.ebpf.runtime.Univ8250Definitions.*;
import static me.bechberger.ebpf.runtime.UnixDefinitions.*;
import static me.bechberger.ebpf.runtime.UnlockDefinitions.*;
import static me.bechberger.ebpf.runtime.UnmapDefinitions.*;
import static me.bechberger.ebpf.runtime.UnregisterDefinitions.*;
import static me.bechberger.ebpf.runtime.UpdateDefinitions.*;
import static me.bechberger.ebpf.runtime.UprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbdevfsDefinitions.*;
import static me.bechberger.ebpf.runtime.UserDefinitions.*;
import static me.bechberger.ebpf.runtime.UserfaultfdDefinitions.*;
import static me.bechberger.ebpf.runtime.Utf8Definitions.*;
import static me.bechberger.ebpf.runtime.UvDefinitions.*;
import static me.bechberger.ebpf.runtime.UvhDefinitions.*;
import static me.bechberger.ebpf.runtime.ValidateDefinitions.*;
import static me.bechberger.ebpf.runtime.VcDefinitions.*;
import static me.bechberger.ebpf.runtime.VcapDefinitions.*;
import static me.bechberger.ebpf.runtime.VcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.VcsDefinitions.*;
import static me.bechberger.ebpf.runtime.VdsoDefinitions.*;
import static me.bechberger.ebpf.runtime.VerifyDefinitions.*;
import static me.bechberger.ebpf.runtime.VfatDefinitions.*;
import static me.bechberger.ebpf.runtime.VfsDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaconDefinitions.*;
import static me.bechberger.ebpf.runtime.ViaDefinitions.*;
import static me.bechberger.ebpf.runtime.ViommuDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtblkDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtioDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtnetDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtscsiDefinitions.*;
import static me.bechberger.ebpf.runtime.VlanDefinitions.*;
import static me.bechberger.ebpf.runtime.VliDefinitions.*;
import static me.bechberger.ebpf.runtime.VmDefinitions.*;
import static me.bechberger.ebpf.runtime.VmaDefinitions.*;
import static me.bechberger.ebpf.runtime.VmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.VmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmeDefinitions.*;
import static me.bechberger.ebpf.runtime.VmemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmpressureDefinitions.*;
import static me.bechberger.ebpf.runtime.VmstatDefinitions.*;
import static me.bechberger.ebpf.runtime.VmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.VpDefinitions.*;
import static me.bechberger.ebpf.runtime.VringDefinitions.*;
import static me.bechberger.ebpf.runtime.VtDefinitions.*;
import static me.bechberger.ebpf.runtime.WaitDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeupDefinitions.*;
import static me.bechberger.ebpf.runtime.WalkDefinitions.*;
import static me.bechberger.ebpf.runtime.WarnDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchdogDefinitions.*;
import static me.bechberger.ebpf.runtime.WbDefinitions.*;
import static me.bechberger.ebpf.runtime.WbtDefinitions.*;
import static me.bechberger.ebpf.runtime.WiphyDefinitions.*;
import static me.bechberger.ebpf.runtime.WirelessDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm831xDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm8350Definitions.*;
import static me.bechberger.ebpf.runtime.WorkqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.WpDefinitions.*;
import static me.bechberger.ebpf.runtime.WqDefinitions.*;
import static me.bechberger.ebpf.runtime.WriteDefinitions.*;
import static me.bechberger.ebpf.runtime.WritebackDefinitions.*;
import static me.bechberger.ebpf.runtime.WwDefinitions.*;
import static me.bechberger.ebpf.runtime.X2apicDefinitions.*;
import static me.bechberger.ebpf.runtime.X509Definitions.*;
import static me.bechberger.ebpf.runtime.X64Definitions.*;
import static me.bechberger.ebpf.runtime.X86Definitions.*;
import static me.bechberger.ebpf.runtime.XaDefinitions.*;
import static me.bechberger.ebpf.runtime.XasDefinitions.*;
import static me.bechberger.ebpf.runtime.XattrDefinitions.*;
import static me.bechberger.ebpf.runtime.XbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdpDefinitions.*;
import static me.bechberger.ebpf.runtime.XenDefinitions.*;
import static me.bechberger.ebpf.runtime.XenbusDefinitions.*;
import static me.bechberger.ebpf.runtime.XennetDefinitions.*;
import static me.bechberger.ebpf.runtime.XenpfDefinitions.*;
import static me.bechberger.ebpf.runtime.Xfrm4Definitions.*;
import static me.bechberger.ebpf.runtime.Xfrm6Definitions.*;
import static me.bechberger.ebpf.runtime.XfrmDefinitions.*;
import static me.bechberger.ebpf.runtime.XhciDefinitions.*;
import static me.bechberger.ebpf.runtime.XpDefinitions.*;
import static me.bechberger.ebpf.runtime.XsDefinitions.*;
import static me.bechberger.ebpf.runtime.XskDefinitions.*;
import static me.bechberger.ebpf.runtime.XtsDefinitions.*;
import static me.bechberger.ebpf.runtime.XzDefinitions.*;
import static me.bechberger.ebpf.runtime.ZapDefinitions.*;
import static me.bechberger.ebpf.runtime.ZlibDefinitions.*;
import static me.bechberger.ebpf.runtime.ZoneDefinitions.*;
import static me.bechberger.ebpf.runtime.ZpoolDefinitions.*;
import static me.bechberger.ebpf.runtime.ZsDefinitions.*;
import static me.bechberger.ebpf.runtime.ZstdDefinitions.*;
import static me.bechberger.ebpf.runtime.ZswapDefinitions.*;
import static me.bechberger.ebpf.runtime.misc.*;
import static me.bechberger.ebpf.runtime.runtime.*;

/**
 * Generated class for BPF runtime types that start with scsi
 */
@java.lang.SuppressWarnings("unused")
public final class ScsiDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<scsi_device> __scsi_add_device(Ptr<Scsi_Host> shost,
      @Unsigned @OriginalName("uint") int channel, @Unsigned @OriginalName("uint") int id,
      @Unsigned long lun, Ptr<?> hostdata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<scsi_device> __scsi_device_lookup(Ptr<Scsi_Host> shost,
      @Unsigned @OriginalName("uint") int channel, @Unsigned @OriginalName("uint") int id,
      @Unsigned long lun) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<scsi_device> __scsi_device_lookup_by_target(Ptr<scsi_target> starget,
      @Unsigned long lun) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__scsi_dh_lookup((const u8*)$arg1)")
  public static Ptr<scsi_device_handler> __scsi_dh_lookup(String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__scsi_format_command($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static @Unsigned long __scsi_format_command(String logbuf, @Unsigned long logbuf_len,
      String cdb, @Unsigned long cdb_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __scsi_host_busy_iter_fn(Ptr<request> req, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__scsi_host_match($arg1, (const void*)$arg2)")
  public static int __scsi_host_match(Ptr<device> dev, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<scsi_device> __scsi_iterate_devices(Ptr<Scsi_Host> shost,
      Ptr<scsi_device> prev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__scsi_print_sense((const struct scsi_device*)$arg1, (const u8*)$arg2, (const u8*)$arg3, $arg4)")
  public static void __scsi_print_sense(Ptr<scsi_device> sdev, String name, String sense_buffer,
      int sense_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __scsi_queue_insert(Ptr<scsi_cmnd> cmd, int reason, boolean unbusy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __scsi_register_driver(Ptr<device_driver> drv, Ptr<module> owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __scsi_remove_device(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __scsi_report_device_reset(Ptr<scsi_device> sdev, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __scsi_scan_target(Ptr<device> parent, @Unsigned int channel, @Unsigned int id,
      @Unsigned long lun, scsi_scan_mode rescan) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_add_device(Ptr<Scsi_Host> host,
      @Unsigned @OriginalName("uint") int channel, @Unsigned @OriginalName("uint") int target,
      @Unsigned long lun) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_add_host_with_dma(Ptr<Scsi_Host> shost, Ptr<device> dev,
      Ptr<device> dma_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_add_lun(Ptr<scsi_device> sdev, String inq_result,
      Ptr<java.lang. @Unsigned @OriginalName("blist_flags_t") Long> bflags, int async) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<request> scsi_alloc_request(Ptr<request_queue> q,
      @Unsigned @OriginalName("blk_opf_t") int opf,
      @Unsigned @OriginalName("blk_mq_req_flags_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<scsi_device> scsi_alloc_sdev(Ptr<scsi_target> starget, @Unsigned long lun,
      Ptr<?> hostdata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("blk_status_t") char scsi_alloc_sgtables(Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<scsi_target> scsi_alloc_target(Ptr<device> parent, int channel,
      @Unsigned @OriginalName("uint") int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_attach_vpd(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_autopm_get_device(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_autopm_get_host(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_autopm_get_target(Ptr<scsi_target> starget) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_autopm_put_device(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_autopm_put_host(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_autopm_put_target(Ptr<scsi_target> starget) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static String scsi_bios_ptable(Ptr<block_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_block_requests(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_block_targets(Ptr<Scsi_Host> shost, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_block_when_processing_errors(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bsg_device> scsi_bsg_register_queue(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_bsg_sg_io_fn(Ptr<request_queue> q, Ptr<sg_io_v4> hdr,
      boolean open_for_write, @Unsigned int timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_build_sense(Ptr<scsi_cmnd> scmd, int desc, char key, char asc,
      char ascq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_build_sense_buffer(int desc, Ptr<java.lang.Character> buf, char key,
      char asc, char ascq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_bus_freeze(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_bus_match($arg1, (const struct device_driver*)$arg2)")
  public static int scsi_bus_match(Ptr<device> dev, Ptr<device_driver> gendrv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_bus_poweroff(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_bus_prepare(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_bus_restore(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_bus_resume(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_bus_suspend(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_bus_thaw(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_bus_uevent((const struct device*)$arg1, $arg2)")
  public static int scsi_bus_uevent(Ptr<device> dev, Ptr<kobj_uevent_env> env) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_cdl_check(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_cdl_enable(Ptr<scsi_device> sdev, boolean enable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_cdrom_send_packet(Ptr<scsi_device> sdev, boolean open_for_write,
      Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_change_queue_depth(Ptr<scsi_device> sdev, int depth) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_check_passthrough(Ptr<scsi_cmnd> scmd, Ptr<scsi_failures> failures) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static scsi_disposition scsi_check_sense(Ptr<scsi_cmnd> scmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_cleanup_rq(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean scsi_cmd_allowed(String cmd, boolean open_for_write) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean scsi_cmd_runtime_exceeced(Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_command_normalize_sense((const struct scsi_cmnd*)$arg1, $arg2)")
  public static boolean scsi_command_normalize_sense(Ptr<scsi_cmnd> cmd,
      Ptr<scsi_sense_hdr> sshdr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_commit_rqs(Ptr<blk_mq_hw_ctx> hctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_complete(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_complete_async_scans() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_dec_host_busy(Ptr<Scsi_Host> shost, Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static scsi_disposition scsi_decide_disposition(Ptr<scsi_cmnd> scmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_dev_info_add_list($arg1, (const u8*)$arg2)")
  public static int scsi_dev_info_add_list(scsi_devinfo_key key, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_dev_info_list_add_keyed(int compatible, String vendor, String model,
      String strflags, @Unsigned @OriginalName("blist_flags_t") long flags, scsi_devinfo_key key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_dev_info_list_add_str(String dev_list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_dev_info_list_find((const u8*)$arg1, (const u8*)$arg2, $arg3)")
  public static Ptr<scsi_dev_info_list> scsi_dev_info_list_find(String vendor, String model,
      scsi_devinfo_key key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_dev_info_remove_list(scsi_devinfo_key key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_device_block(Ptr<scsi_device> sdev, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_device_cls_release(Ptr<device> class_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_device_dev_release(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<scsi_device> scsi_device_from_queue(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_device_get(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<scsi_device> scsi_device_lookup(Ptr<Scsi_Host> shost,
      @Unsigned @OriginalName("uint") int channel, @Unsigned @OriginalName("uint") int id,
      @Unsigned long lun) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<scsi_device> scsi_device_lookup_by_target(Ptr<scsi_target> starget,
      @Unsigned long lun) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_device_max_queue_depth(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_device_put(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_device_quiesce(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_device_resume(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_device_set_state(Ptr<scsi_device> sdev, scsi_device_state state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)scsi_device_state_name($arg1))")
  public static String scsi_device_state_name(scsi_device_state state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)scsi_device_type($arg1))")
  public static String scsi_device_type(@Unsigned int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_device_unbusy(Ptr<scsi_device> sdev, Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_dh_activate(Ptr<request_queue> q,
      @OriginalName("activate_complete") Ptr<?> fn, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_dh_add_device(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_dh_attach($arg1, (const u8*)$arg2)")
  public static int scsi_dh_attach(Ptr<request_queue> q, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)scsi_dh_attached_handler_name($arg1, $arg2))")
  public static String scsi_dh_attached_handler_name(Ptr<request_queue> q,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)scsi_dh_find_driver($arg1))")
  public static String scsi_dh_find_driver(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_dh_handler_attach(Ptr<scsi_device> sdev,
      Ptr<scsi_device_handler> scsi_dh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_dh_release_device(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_dh_set_params($arg1, (const u8*)$arg2)")
  public static int scsi_dh_set_params(Ptr<request_queue> q, String params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_disk_free_disk(Ptr<gendisk> disk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_disk_release(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_dispatch_cmd(Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_dma_map(Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_dma_unmap(Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_done(Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_done_direct(Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_done_internal(Ptr<scsi_cmnd> cmd, boolean complete_directly) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_eh_bus_device_reset(Ptr<Scsi_Host> shost, Ptr<list_head> work_q,
      Ptr<list_head> done_q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_eh_bus_reset(Ptr<Scsi_Host> shost, Ptr<list_head> work_q,
      Ptr<list_head> done_q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_eh_done(Ptr<scsi_cmnd> scmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_eh_finish_cmd(Ptr<scsi_cmnd> scmd, Ptr<list_head> done_q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_eh_flush_done_q(Ptr<list_head> done_q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_eh_get_sense(Ptr<list_head> work_q, Ptr<list_head> done_q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_eh_inc_host_failed(Ptr<callback_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_eh_prep_cmnd(Ptr<scsi_cmnd> scmd, Ptr<scsi_eh_save> ses, String cmnd,
      int cmnd_size, @Unsigned int sense_bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_eh_ready_devs(Ptr<Scsi_Host> shost, Ptr<list_head> work_q,
      Ptr<list_head> done_q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_eh_restore_cmnd(Ptr<scsi_cmnd> scmd, Ptr<scsi_eh_save> ses) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_eh_scmd_add(Ptr<scsi_cmnd> scmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_eh_stu(Ptr<Scsi_Host> shost, Ptr<list_head> work_q,
      Ptr<list_head> done_q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_eh_target_reset(Ptr<Scsi_Host> shost, Ptr<list_head> work_q,
      Ptr<list_head> done_q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_eh_test_devices(Ptr<list_head> cmd_list, Ptr<list_head> work_q,
      Ptr<list_head> done_q, int try_stu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_eh_try_stu(Ptr<scsi_cmnd> scmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_eh_tur(Ptr<scsi_cmnd> scmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_eh_wakeup(Ptr<Scsi_Host> shost, @Unsigned int busy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_enable_async_suspend(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean scsi_end_request(Ptr<request> req, @OriginalName("blk_status_t") char error,
      @Unsigned int bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_error_handler(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_evt_thread(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_execute_cmd($arg1, (const u8*)$arg2, $arg3, $arg4, $arg5, $arg6, $arg7, (const struct scsi_exec_args*)$arg8)")
  public static int scsi_execute_cmd(Ptr<scsi_device> sdev, String cmd,
      @Unsigned @OriginalName("blk_opf_t") int opf, Ptr<?> buffer, @Unsigned int bufflen,
      int timeout, int ml_retries, Ptr<scsi_exec_args> args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_exit_devinfo() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_exit_hosts() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_exit_procfs() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_exit_queue() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_exit_sysctl() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)scsi_extd_sense_format($arg1, $arg2, (const u8**)$arg3))")
  public static String scsi_extd_sense_format(char asc, char ascq, Ptr<String> fmt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_failures_reset_retries(Ptr<scsi_failures> failures) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_finish_command(Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_flush_work(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_forget_host(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_format_opcode_name($arg1, $arg2, (const u8*)$arg3)")
  public static @Unsigned long scsi_format_opcode_name(String buffer, @Unsigned long buf_len,
      String cdbp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_free_sgtables(Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_get_cdrom_generic_arg($arg1, (const void*)$arg2)")
  public static int scsi_get_cdrom_generic_arg(Ptr<cdrom_generic_command> cgc, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_get_device_flags($arg1, (const u8*)$arg2, (const u8*)$arg3)")
  public static @Unsigned @OriginalName("blist_flags_t") long scsi_get_device_flags(
      Ptr<scsi_device> sdev, String vendor, String model) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_get_device_flags_keyed($arg1, (const u8*)$arg2, (const u8*)$arg3, $arg4)")
  public static @Unsigned @OriginalName("blist_flags_t") long scsi_get_device_flags_keyed(
      Ptr<scsi_device> sdev, String vendor, String model, scsi_devinfo_key key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_get_sense_info_fld((const u8*)$arg1, $arg2, $arg3)")
  public static boolean scsi_get_sense_info_fld(Ptr<java.lang.Character> sense_buffer, int sb_len,
      Ptr<java.lang. @Unsigned Long> info_out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<scsi_vpd> scsi_get_vpd_buf(Ptr<scsi_device> sdev, char page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_get_vpd_page(Ptr<scsi_device> sdev, char page, String buf, int buf_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_get_vpd_size(Ptr<scsi_device> sdev, char page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_handle_queue_full(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_handle_queue_ramp_up(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_host_alloc((const struct scsi_host_template*)$arg1, $arg2)")
  public static Ptr<Scsi_Host> scsi_host_alloc(Ptr<scsi_host_template> sht, int privsize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_host_block(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_host_busy(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_host_busy_iter($arg1, (_Bool (*)(struct scsi_cmnd*, void*))$arg2, $arg3)")
  public static void scsi_host_busy_iter(Ptr<Scsi_Host> shost, Ptr<?> fn, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean scsi_host_check_in_flight(Ptr<request> rq, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_host_cls_release(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_host_complete_all_commands(Ptr<Scsi_Host> shost,
      scsi_host_status status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_host_dev_release(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<Scsi_Host> scsi_host_get(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<Scsi_Host> scsi_host_lookup(@Unsigned int hostnum) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_host_put(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_host_set_state(Ptr<Scsi_Host> shost, scsi_host_state state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)scsi_host_state_name($arg1))")
  public static String scsi_host_state_name(scsi_host_state state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_host_unblock(Ptr<Scsi_Host> shost, int new_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)scsi_hostbyte_string($arg1))")
  public static String scsi_hostbyte_string(int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_init_command(Ptr<scsi_device> dev, Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_init_devinfo() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_init_hctx(Ptr<blk_mq_hw_ctx> hctx, Ptr<?> data, @Unsigned int hctx_idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_init_hosts() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_init_limits(Ptr<Scsi_Host> shost, Ptr<queue_limits> lim) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_init_procfs() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_init_sense_cache(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_init_sysctl() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_initialize_rq(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_internal_device_block_nowait(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_internal_device_unblock_nowait(Ptr<scsi_device> sdev,
      scsi_device_state new_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_io_completion(Ptr<scsi_cmnd> cmd, @Unsigned int good_bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_io_completion_action(Ptr<scsi_cmnd> cmd, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_ioctl(Ptr<scsi_device> sdev, boolean open_for_write, int cmd, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_ioctl_block_when_processing_errors(Ptr<scsi_device> sdev, int cmd,
      boolean ndelay) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_ioctl_get_pci(Ptr<scsi_device> sdev, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_ioctl_reset(Ptr<scsi_device> dev, Ptr<java.lang.Integer> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_is_host_device((const struct device*)$arg1)")
  public static int scsi_is_host_device(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_is_sdev_device((const struct device*)$arg1)")
  public static int scsi_is_sdev_device(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_is_target_device((const struct device*)$arg1)")
  public static int scsi_is_target_device(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_kick_sdev_queue(Ptr<scsi_device> sdev, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> scsi_kmap_atomic_sg(Ptr<scatterlist> sgl, int sg_count,
      Ptr<java.lang. @Unsigned Long> offset, Ptr<java.lang. @Unsigned Long> len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_kunmap_atomic_sg(Ptr<?> virt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_log_completion(Ptr<scsi_cmnd> cmd, int disposition) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_log_print_sense((const struct scsi_device*)$arg1, (const u8*)$arg2, $arg3, (const u8*)$arg4, $arg5)")
  public static void scsi_log_print_sense(Ptr<scsi_device> sdev, String name, int tag,
      String sense_buffer, int sense_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_log_print_sense_hdr((const struct scsi_device*)$arg1, (const u8*)$arg2, $arg3, (const struct scsi_sense_hdr*)$arg4)")
  public static void scsi_log_print_sense_hdr(Ptr<scsi_device> sdev, String name, int tag,
      Ptr<scsi_sense_hdr> sshdr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static String scsi_log_reserve_buffer(Ptr<java.lang. @Unsigned Long> len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_log_send(Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_map_queues(Ptr<blk_mq_tag_set> set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)scsi_mlreturn_string($arg1))")
  public static String scsi_mlreturn_string(int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_mode_select(Ptr<scsi_device> sdev, int pf, int sp, String buffer, int len,
      int timeout, int retries, Ptr<scsi_mode_data> data, Ptr<scsi_sense_hdr> sshdr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_mode_sense(Ptr<scsi_device> sdev, int dbd, int modepage, int subpage,
      String buffer, int len, int timeout, int retries, Ptr<scsi_mode_data> data,
      Ptr<scsi_sense_hdr> sshdr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_mq_exit_request(Ptr<blk_mq_tag_set> set, Ptr<request> rq,
      @Unsigned int hctx_idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_mq_free_tags(Ptr<kref> kref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_mq_get_budget(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_mq_get_rq_budget_token(Ptr<request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_mq_init_request(Ptr<blk_mq_tag_set> set, Ptr<request> rq,
      @Unsigned int hctx_idx, @Unsigned int numa_node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean scsi_mq_lld_busy(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_mq_poll(Ptr<blk_mq_hw_ctx> hctx, Ptr<io_comp_batch> iob) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_mq_put_budget(Ptr<request_queue> q, int budget_token) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_mq_requeue_cmd(Ptr<scsi_cmnd> cmd, @Unsigned long msecs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_mq_set_rq_budget_token(Ptr<request> req, int token) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_mq_setup_tags(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_netlink_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_netlink_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_nl_rcv_msg(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean scsi_noretry_cmd(Ptr<scsi_cmnd> scmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_normalize_sense((const u8*)$arg1, $arg2, $arg3)")
  public static boolean scsi_normalize_sense(Ptr<java.lang.Character> sense_buffer, int sb_len,
      Ptr<scsi_sense_hdr> sshdr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_opcode_sa_name($arg1, $arg2, (const u8**)$arg3, (const u8**)$arg4)")
  public static boolean scsi_opcode_sa_name(int opcode, int service_action, Ptr<String> cdb_name,
      Ptr<String> sa_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean scsi_partsize(Ptr<block_device> bdev,
      @Unsigned @OriginalName("sector_t") long capacity, Ptr<java.lang.Integer> geom) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static pr_type scsi_pr_type_to_block(scsi_pr_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("blk_status_t") char scsi_prepare_cmd(Ptr<request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_print_command(Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_print_result((const struct scsi_cmnd*)$arg1, (const u8*)$arg2, $arg3)")
  public static void scsi_print_result(Ptr<scsi_cmnd> cmd, String msg, int disposition) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_print_sense((const struct scsi_cmnd*)$arg1)")
  public static void scsi_print_sense(Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_print_sense_hdr((const struct scsi_device*)$arg1, (const u8*)$arg2, (const struct scsi_sense_hdr*)$arg3)")
  public static void scsi_print_sense_hdr(Ptr<scsi_device> sdev, String name,
      Ptr<scsi_sense_hdr> sshdr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_probe_and_add_lun(Ptr<scsi_target> starget, @Unsigned long lun,
      Ptr<java.lang. @Unsigned @OriginalName("blist_flags_t") Long> bflagsp,
      Ptr<Ptr<scsi_device>> sdevp, scsi_scan_mode rescan, Ptr<?> hostdata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_proc_host_add(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_proc_host_rm(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_proc_hostdir_add((const struct scsi_host_template*)$arg1)")
  public static int scsi_proc_hostdir_add(Ptr<scsi_host_template> sht) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_proc_hostdir_rm((const struct scsi_host_template*)$arg1)")
  public static void scsi_proc_hostdir_rm(Ptr<scsi_host_template> sht) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_queue_insert(Ptr<scsi_cmnd> cmd, int reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_queue_rq($arg1, (const struct blk_mq_queue_data*)$arg2)")
  public static @OriginalName("blk_status_t") char scsi_queue_rq(Ptr<blk_mq_hw_ctx> hctx,
      Ptr<blk_mq_queue_data> bd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_queue_work(Ptr<Scsi_Host> shost, Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_realloc_sdev_budget_map(Ptr<scsi_device> sdev, @Unsigned int depth) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_register_device_handler(Ptr<scsi_device_handler> scsi_dh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_register_interface(Ptr<class_interface> intf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_remove_device(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_remove_host(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_remove_target(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_report_bus_reset(Ptr<Scsi_Host> shost, int channel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_report_device_reset(Ptr<Scsi_Host> shost, int channel, int target) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_report_lun_scan(Ptr<scsi_target> starget,
      @Unsigned @OriginalName("blist_flags_t") long bflags, scsi_scan_mode rescan) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_report_opcode(Ptr<scsi_device> sdev, String buffer, @Unsigned int len,
      char opcode, @Unsigned short sa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_report_sense(Ptr<scsi_device> sdev, Ptr<scsi_sense_hdr> sshdr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_requeue_run_queue(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_rescan_device(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_restart_operations(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("blk_status_t") char scsi_result_to_blk_status(int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_resume_device(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_run_host_queues(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_run_queue(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_run_queue_async(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_runtime_idle(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_runtime_resume(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_runtime_suspend(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_sanitize_inquiry_string(String s, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_scan_channel(Ptr<Scsi_Host> shost, @Unsigned int channel,
      @Unsigned int id, @Unsigned long lun, scsi_scan_mode rescan) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_scan_host(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_scan_host_selected(Ptr<Scsi_Host> shost, @Unsigned int channel,
      @Unsigned int id, @Unsigned long lun, scsi_scan_mode rescan) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_scan_target(Ptr<device> parent, @Unsigned int channel, @Unsigned int id,
      @Unsigned long lun, scsi_scan_mode rescan) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_schedule_eh(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("umode_t") short scsi_sdev_attr_is_visible(
      Ptr<kobject> kobj, Ptr<attribute> attr, int i) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_sdev_bin_attr_is_visible($arg1, (const struct bin_attribute*)$arg2, $arg3)")
  public static @Unsigned @OriginalName("umode_t") short scsi_sdev_bin_attr_is_visible(
      Ptr<kobject> kobj, Ptr<bin_attribute> attr, int i) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static scsi_disposition scsi_send_eh_cmnd(Ptr<scsi_cmnd> scmd, String cmnd, int cmnd_size,
      int timeout, @Unsigned int sense_bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)scsi_sense_desc_find((const u8*)$arg1, $arg2, $arg3))")
  public static Ptr<java.lang.Character> scsi_sense_desc_find(Ptr<java.lang.Character> sense_buffer,
      int sb_len, int desc_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)scsi_sense_key_string($arg1))")
  public static String scsi_sense_key_string(char key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> scsi_seq_next(Ptr<seq_file> sfile, Ptr<?> v,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_seq_show(Ptr<seq_file> sfile, Ptr<?> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> scsi_seq_start(Ptr<seq_file> sfile,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_seq_stop(Ptr<seq_file> sfile, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_set_medium_removal(Ptr<scsi_device> sdev, char state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_set_sense_field_pointer(Ptr<java.lang.Character> buf, int buf_len,
      @Unsigned short fp, char bp, boolean cd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_set_sense_information(Ptr<java.lang.Character> buf, int buf_len,
      @Unsigned long info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_show_rq(Ptr<seq_file> m, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_start_queue(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_starved_list_run(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean scsi_status_is_good(int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_strcpy_devinfo(String name, String to, @Unsigned long to_length,
      String from, int compatible) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_sysfs_add_host(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_sysfs_add_sdev(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_sysfs_device_initialize(Ptr<scsi_device> sdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_sysfs_register() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_sysfs_unregister() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_target_destroy(Ptr<scsi_target> starget) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_target_dev_release(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_target_quiesce(Ptr<scsi_target> starget) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_target_reap(Ptr<scsi_target> starget) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_target_resume(Ptr<scsi_target> starget) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_target_unblock(Ptr<device> dev, scsi_device_state new_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scsi_template_proc_dir((const struct scsi_host_template*)$arg1)")
  public static Ptr<proc_dir_entry> scsi_template_proc_dir(Ptr<scsi_host_template> sht) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_test_unit_ready(Ptr<scsi_device> sdev, int timeout, int retries,
      Ptr<scsi_sense_hdr> sshdr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static blk_eh_timer_return scsi_timeout(Ptr<request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)scsi_trace_parse_cdb($arg1, $arg2, $arg3))")
  public static String scsi_trace_parse_cdb(Ptr<trace_seq> p, String cdb, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_track_queue_full(Ptr<scsi_device> sdev, int depth) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static scsi_disposition scsi_try_bus_reset(Ptr<scsi_cmnd> scmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static scsi_disposition scsi_try_host_reset(Ptr<scsi_cmnd> scmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static scsi_disposition scsi_try_target_reset(Ptr<scsi_cmnd> scmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_unblock_requests(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scsi_unjam_host(Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_unregister_device_handler(Ptr<scsi_device_handler> scsi_dh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_vpd_inquiry(Ptr<scsi_device> sdev, String buffer, char page,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_vpd_lun_id(Ptr<scsi_device> sdev, String id, @Unsigned long id_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scsi_vpd_tpg_id(Ptr<scsi_device> sdev, Ptr<java.lang.Integer> rel_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int id; long long unsigned int lun; short unsigned int reserved1; unsigned int reserved2; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_of_device_path_of_edd_device_params extends Struct {
    public @Unsigned short id;

    public @Unsigned long lun;

    public @Unsigned short reserved1;

    public @Unsigned int reserved2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scsi_device_event"
  )
  public enum scsi_device_event implements Enum<scsi_device_event>, TypedEnum<scsi_device_event, java.lang. @Unsigned Integer> {
    /**
     * {@code SDEV_EVT_MEDIA_CHANGE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SDEV_EVT_MEDIA_CHANGE"
    )
    SDEV_EVT_MEDIA_CHANGE,

    /**
     * {@code SDEV_EVT_INQUIRY_CHANGE_REPORTED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SDEV_EVT_INQUIRY_CHANGE_REPORTED"
    )
    SDEV_EVT_INQUIRY_CHANGE_REPORTED,

    /**
     * {@code SDEV_EVT_CAPACITY_CHANGE_REPORTED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SDEV_EVT_CAPACITY_CHANGE_REPORTED"
    )
    SDEV_EVT_CAPACITY_CHANGE_REPORTED,

    /**
     * {@code SDEV_EVT_SOFT_THRESHOLD_REACHED_REPORTED = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SDEV_EVT_SOFT_THRESHOLD_REACHED_REPORTED"
    )
    SDEV_EVT_SOFT_THRESHOLD_REACHED_REPORTED,

    /**
     * {@code SDEV_EVT_MODE_PARAMETER_CHANGE_REPORTED = 5}
     */
    @EnumMember(
        value = 5L,
        name = "SDEV_EVT_MODE_PARAMETER_CHANGE_REPORTED"
    )
    SDEV_EVT_MODE_PARAMETER_CHANGE_REPORTED,

    /**
     * {@code SDEV_EVT_LUN_CHANGE_REPORTED = 6}
     */
    @EnumMember(
        value = 6L,
        name = "SDEV_EVT_LUN_CHANGE_REPORTED"
    )
    SDEV_EVT_LUN_CHANGE_REPORTED,

    /**
     * {@code SDEV_EVT_ALUA_STATE_CHANGE_REPORTED = 7}
     */
    @EnumMember(
        value = 7L,
        name = "SDEV_EVT_ALUA_STATE_CHANGE_REPORTED"
    )
    SDEV_EVT_ALUA_STATE_CHANGE_REPORTED,

    /**
     * {@code SDEV_EVT_POWER_ON_RESET_OCCURRED = 8}
     */
    @EnumMember(
        value = 8L,
        name = "SDEV_EVT_POWER_ON_RESET_OCCURRED"
    )
    SDEV_EVT_POWER_ON_RESET_OCCURRED,

    /**
     * {@code SDEV_EVT_FIRST = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SDEV_EVT_FIRST"
    )
    SDEV_EVT_FIRST,

    /**
     * {@code SDEV_EVT_LAST = 8}
     */
    @EnumMember(
        value = 8L,
        name = "SDEV_EVT_LAST"
    )
    SDEV_EVT_LAST,

    /**
     * {@code SDEV_EVT_MAXBITS = 9}
     */
    @EnumMember(
        value = 9L,
        name = "SDEV_EVT_MAXBITS"
    )
    SDEV_EVT_MAXBITS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_sense_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_sense_hdr extends Struct {
    public char response_code;

    public char sense_key;

    public char asc;

    public char ascq;

    public char byte4;

    public char byte5;

    public char byte6;

    public char additional_length;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scsi_host_status"
  )
  public enum scsi_host_status implements Enum<scsi_host_status>, TypedEnum<scsi_host_status, java.lang. @Unsigned Integer> {
    /**
     * {@code DID_OK = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DID_OK"
    )
    DID_OK,

    /**
     * {@code DID_NO_CONNECT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DID_NO_CONNECT"
    )
    DID_NO_CONNECT,

    /**
     * {@code DID_BUS_BUSY = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DID_BUS_BUSY"
    )
    DID_BUS_BUSY,

    /**
     * {@code DID_TIME_OUT = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DID_TIME_OUT"
    )
    DID_TIME_OUT,

    /**
     * {@code DID_BAD_TARGET = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DID_BAD_TARGET"
    )
    DID_BAD_TARGET,

    /**
     * {@code DID_ABORT = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DID_ABORT"
    )
    DID_ABORT,

    /**
     * {@code DID_PARITY = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DID_PARITY"
    )
    DID_PARITY,

    /**
     * {@code DID_ERROR = 7}
     */
    @EnumMember(
        value = 7L,
        name = "DID_ERROR"
    )
    DID_ERROR,

    /**
     * {@code DID_RESET = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DID_RESET"
    )
    DID_RESET,

    /**
     * {@code DID_BAD_INTR = 9}
     */
    @EnumMember(
        value = 9L,
        name = "DID_BAD_INTR"
    )
    DID_BAD_INTR,

    /**
     * {@code DID_PASSTHROUGH = 10}
     */
    @EnumMember(
        value = 10L,
        name = "DID_PASSTHROUGH"
    )
    DID_PASSTHROUGH,

    /**
     * {@code DID_SOFT_ERROR = 11}
     */
    @EnumMember(
        value = 11L,
        name = "DID_SOFT_ERROR"
    )
    DID_SOFT_ERROR,

    /**
     * {@code DID_IMM_RETRY = 12}
     */
    @EnumMember(
        value = 12L,
        name = "DID_IMM_RETRY"
    )
    DID_IMM_RETRY,

    /**
     * {@code DID_REQUEUE = 13}
     */
    @EnumMember(
        value = 13L,
        name = "DID_REQUEUE"
    )
    DID_REQUEUE,

    /**
     * {@code DID_TRANSPORT_DISRUPTED = 14}
     */
    @EnumMember(
        value = 14L,
        name = "DID_TRANSPORT_DISRUPTED"
    )
    DID_TRANSPORT_DISRUPTED,

    /**
     * {@code DID_TRANSPORT_FAILFAST = 15}
     */
    @EnumMember(
        value = 15L,
        name = "DID_TRANSPORT_FAILFAST"
    )
    DID_TRANSPORT_FAILFAST,

    /**
     * {@code DID_TRANSPORT_MARGINAL = 20}
     */
    @EnumMember(
        value = 20L,
        name = "DID_TRANSPORT_MARGINAL"
    )
    DID_TRANSPORT_MARGINAL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scsi_disposition"
  )
  public enum scsi_disposition implements Enum<scsi_disposition>, TypedEnum<scsi_disposition, java.lang. @Unsigned Integer> {
    /**
     * {@code NEEDS_RETRY = 8193}
     */
    @EnumMember(
        value = 8193L,
        name = "NEEDS_RETRY"
    )
    NEEDS_RETRY,

    /**
     * {@code SUCCESS = 8194}
     */
    @EnumMember(
        value = 8194L,
        name = "SUCCESS"
    )
    SUCCESS,

    /**
     * {@code FAILED = 8195}
     */
    @EnumMember(
        value = 8195L,
        name = "FAILED"
    )
    FAILED,

    /**
     * {@code QUEUED = 8196}
     */
    @EnumMember(
        value = 8196L,
        name = "QUEUED"
    )
    QUEUED,

    /**
     * {@code SOFT_ERROR = 8197}
     */
    @EnumMember(
        value = 8197L,
        name = "SOFT_ERROR"
    )
    SOFT_ERROR,

    /**
     * {@code ADD_TO_MLQUEUE = 8198}
     */
    @EnumMember(
        value = 8198L,
        name = "ADD_TO_MLQUEUE"
    )
    ADD_TO_MLQUEUE,

    /**
     * {@code TIMEOUT_ERROR = 8199}
     */
    @EnumMember(
        value = 8199L,
        name = "TIMEOUT_ERROR"
    )
    TIMEOUT_ERROR,

    /**
     * {@code SCSI_RETURN_NOT_HANDLED = 8200}
     */
    @EnumMember(
        value = 8200L,
        name = "SCSI_RETURN_NOT_HANDLED"
    )
    SCSI_RETURN_NOT_HANDLED,

    /**
     * {@code FAST_IO_FAIL = 8201}
     */
    @EnumMember(
        value = 8201L,
        name = "FAST_IO_FAIL"
    )
    FAST_IO_FAIL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_mode_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_mode_data extends Struct {
    public @Unsigned int length;

    public @Unsigned short block_descriptor_length;

    public char medium_type;

    public char device_specific;

    public char header_length;

    public char longlba;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scsi_device_state"
  )
  public enum scsi_device_state implements Enum<scsi_device_state>, TypedEnum<scsi_device_state, java.lang. @Unsigned Integer> {
    /**
     * {@code SDEV_CREATED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SDEV_CREATED"
    )
    SDEV_CREATED,

    /**
     * {@code SDEV_RUNNING = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SDEV_RUNNING"
    )
    SDEV_RUNNING,

    /**
     * {@code SDEV_CANCEL = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SDEV_CANCEL"
    )
    SDEV_CANCEL,

    /**
     * {@code SDEV_DEL = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SDEV_DEL"
    )
    SDEV_DEL,

    /**
     * {@code SDEV_QUIESCE = 5}
     */
    @EnumMember(
        value = 5L,
        name = "SDEV_QUIESCE"
    )
    SDEV_QUIESCE,

    /**
     * {@code SDEV_OFFLINE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "SDEV_OFFLINE"
    )
    SDEV_OFFLINE,

    /**
     * {@code SDEV_TRANSPORT_OFFLINE = 7}
     */
    @EnumMember(
        value = 7L,
        name = "SDEV_TRANSPORT_OFFLINE"
    )
    SDEV_TRANSPORT_OFFLINE,

    /**
     * {@code SDEV_BLOCK = 8}
     */
    @EnumMember(
        value = 8L,
        name = "SDEV_BLOCK"
    )
    SDEV_BLOCK,

    /**
     * {@code SDEV_CREATED_BLOCK = 9}
     */
    @EnumMember(
        value = 9L,
        name = "SDEV_CREATED_BLOCK"
    )
    SDEV_CREATED_BLOCK
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_vpd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_vpd extends Struct {
    public callback_head rcu;

    public int len;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_device"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_device extends Struct {
    public Ptr<Scsi_Host> host;

    public Ptr<request_queue> request_queue;

    public list_head siblings;

    public list_head same_target_siblings;

    public sbitmap budget_map;

    public atomic_t device_blocked;

    public atomic_t restarts;

    public @OriginalName("spinlock_t") spinlock list_lock;

    public list_head starved_entry;

    public @Unsigned short queue_depth;

    public @Unsigned short max_queue_depth;

    public @Unsigned short last_queue_full_depth;

    public @Unsigned short last_queue_full_count;

    public @Unsigned long last_queue_full_time;

    public @Unsigned long queue_ramp_up_period;

    public @Unsigned long last_queue_ramp_up;

    public @Unsigned int id;

    public @Unsigned int channel;

    public @Unsigned long lun;

    public @Unsigned int manufacturer;

    public @Unsigned int sector_size;

    public Ptr<?> hostdata;

    public char type;

    public char scsi_level;

    public char inq_periph_qual;

    public mutex inquiry_mutex;

    public char inquiry_len;

    public String inquiry;

    public String vendor;

    public String model;

    public String rev;

    public Ptr<scsi_vpd> vpd_pg0;

    public Ptr<scsi_vpd> vpd_pg83;

    public Ptr<scsi_vpd> vpd_pg80;

    public Ptr<scsi_vpd> vpd_pg89;

    public Ptr<scsi_vpd> vpd_pgb0;

    public Ptr<scsi_vpd> vpd_pgb1;

    public Ptr<scsi_vpd> vpd_pgb2;

    public Ptr<scsi_vpd> vpd_pgb7;

    public Ptr<scsi_target> sdev_target;

    public @Unsigned @OriginalName("blist_flags_t") long sdev_bflags;

    public @Unsigned int eh_timeout;

    public @Unsigned int manage_system_start_stop;

    public @Unsigned int manage_runtime_start_stop;

    public @Unsigned int manage_shutdown;

    public @Unsigned int force_runtime_start_on_system_start;

    public @Unsigned int is_ata;

    public @Unsigned int removable;

    public @Unsigned int changed;

    public @Unsigned int busy;

    public @Unsigned int lockable;

    public @Unsigned int locked;

    public @Unsigned int borken;

    public @Unsigned int disconnect;

    public @Unsigned int soft_reset;

    public @Unsigned int sdtr;

    public @Unsigned int wdtr;

    public @Unsigned int ppr;

    public @Unsigned int tagged_supported;

    public @Unsigned int simple_tags;

    public @Unsigned int was_reset;

    public @Unsigned int expecting_cc_ua;

    public @Unsigned int use_10_for_rw;

    public @Unsigned int use_10_for_ms;

    public @Unsigned int set_dbd_for_ms;

    public @Unsigned int read_before_ms;

    public @Unsigned int no_report_opcodes;

    public @Unsigned int no_write_same;

    public @Unsigned int use_16_for_rw;

    public @Unsigned int use_16_for_sync;

    public @Unsigned int skip_ms_page_8;

    public @Unsigned int skip_ms_page_3f;

    public @Unsigned int skip_vpd_pages;

    public @Unsigned int try_vpd_pages;

    public @Unsigned int use_192_bytes_for_3f;

    public @Unsigned int no_start_on_add;

    public @Unsigned int allow_restart;

    public @Unsigned int start_stop_pwr_cond;

    public @Unsigned int no_uld_attach;

    public @Unsigned int select_no_atn;

    public @Unsigned int fix_capacity;

    public @Unsigned int guess_capacity;

    public @Unsigned int retry_hwerror;

    public @Unsigned int last_sector_bug;

    public @Unsigned int no_read_disc_info;

    public @Unsigned int no_read_capacity_16;

    public @Unsigned int try_rc_10_first;

    public @Unsigned int security_supported;

    public @Unsigned int is_visible;

    public @Unsigned int wce_default_on;

    public @Unsigned int no_dif;

    public @Unsigned int broken_fua;

    public @Unsigned int lun_in_cdb;

    public @Unsigned int unmap_limit_for_ws;

    public @Unsigned int rpm_autosuspend;

    public @Unsigned int ignore_media_change;

    public @Unsigned int silence_suspend;

    public @Unsigned int no_vpd_size;

    public @Unsigned int cdl_supported;

    public @Unsigned int cdl_enable;

    public @Unsigned int queue_stopped;

    public boolean offline_already;

    public atomic_t ua_new_media_ctr;

    public atomic_t ua_por_ctr;

    public atomic_t disk_events_disable_depth;

    public @Unsigned long @Size(1) [] supported_events;

    public @Unsigned long @Size(1) [] pending_events;

    public list_head event_list;

    public work_struct event_work;

    public @Unsigned int max_device_blocked;

    public atomic_t iorequest_cnt;

    public atomic_t iodone_cnt;

    public atomic_t ioerr_cnt;

    public atomic_t iotmo_cnt;

    public device sdev_gendev;

    public device sdev_dev;

    public work_struct requeue_work;

    public Ptr<scsi_device_handler> handler;

    public Ptr<?> handler_data;

    public @Unsigned long dma_drain_len;

    public Ptr<?> dma_drain_buf;

    public @Unsigned int sg_timeout;

    public @Unsigned int sg_reserved_size;

    public Ptr<bsg_device> bsg_dev;

    public char access_state;

    public mutex state_mutex;

    public scsi_device_state sdev_state;

    public Ptr<task_struct> quiesced_by;

    public @Unsigned long @Size(0) [] sdev_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_target"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_target extends Struct {
    public Ptr<scsi_device> starget_sdev_user;

    public list_head siblings;

    public list_head devices;

    public device dev;

    public kref reap_ref;

    public @Unsigned int channel;

    public @Unsigned int id;

    public @Unsigned int create;

    public @Unsigned int single_lun;

    public @Unsigned int pdt_1f_for_no_lun;

    public @Unsigned int no_report_luns;

    public @Unsigned int expecting_lun_change;

    public atomic_t target_busy;

    public atomic_t target_blocked;

    public @Unsigned int can_queue;

    public @Unsigned int max_target_blocked;

    public char scsi_level;

    public scsi_target_state state;

    public Ptr<?> hostdata;

    public @Unsigned long @Size(0) [] starget_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scsi_target_state"
  )
  public enum scsi_target_state implements Enum<scsi_target_state>, TypedEnum<scsi_target_state, java.lang. @Unsigned Integer> {
    /**
     * {@code STARGET_CREATED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "STARGET_CREATED"
    )
    STARGET_CREATED,

    /**
     * {@code STARGET_RUNNING = 2}
     */
    @EnumMember(
        value = 2L,
        name = "STARGET_RUNNING"
    )
    STARGET_RUNNING,

    /**
     * {@code STARGET_REMOVE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "STARGET_REMOVE"
    )
    STARGET_REMOVE,

    /**
     * {@code STARGET_CREATED_REMOVE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "STARGET_CREATED_REMOVE"
    )
    STARGET_CREATED_REMOVE,

    /**
     * {@code STARGET_DEL = 5}
     */
    @EnumMember(
        value = 5L,
        name = "STARGET_DEL"
    )
    STARGET_DEL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_failure"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_failure extends Struct {
    public int result;

    public char sense;

    public char asc;

    public char ascq;

    public @OriginalName("s8") byte allowed;

    public @OriginalName("s8") byte retries;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_failures"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_failures extends Struct {
    public int total_allowed;

    public int total_retries;

    public Ptr<scsi_failure> failure_definitions;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_exec_args"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_exec_args extends Struct {
    public String sense;

    public @Unsigned int sense_len;

    public Ptr<scsi_sense_hdr> sshdr;

    public @Unsigned @OriginalName("blk_mq_req_flags_t") int req_flags;

    public int scmd_flags;

    public Ptr<java.lang.Integer> resid;

    public Ptr<scsi_failures> failures;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_data_buffer"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_data_buffer extends Struct {
    public sg_table table;

    public @Unsigned int length;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scsi_cmnd_submitter"
  )
  public enum scsi_cmnd_submitter implements Enum<scsi_cmnd_submitter>, TypedEnum<scsi_cmnd_submitter, java.lang.Boolean> {
    /**
     * {@code SUBMITTED_BY_BLOCK_LAYER = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SUBMITTED_BY_BLOCK_LAYER"
    )
    SUBMITTED_BY_BLOCK_LAYER,

    /**
     * {@code SUBMITTED_BY_SCSI_ERROR_HANDLER = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SUBMITTED_BY_SCSI_ERROR_HANDLER"
    )
    SUBMITTED_BY_SCSI_ERROR_HANDLER,

    /**
     * {@code SUBMITTED_BY_SCSI_RESET_IOCTL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SUBMITTED_BY_SCSI_RESET_IOCTL"
    )
    SUBMITTED_BY_SCSI_RESET_IOCTL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_cmnd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_cmnd extends Struct {
    public Ptr<scsi_device> device;

    public list_head eh_entry;

    public delayed_work abort_work;

    public callback_head rcu;

    public int eh_eflags;

    public int budget_token;

    public @Unsigned long jiffies_at_alloc;

    public int retries;

    public int allowed;

    public char prot_op;

    public char prot_type;

    public char prot_flags;

    public scsi_cmnd_submitter submitter;

    public @Unsigned short cmd_len;

    public dma_data_direction sc_data_direction;

    public char @Size(32) [] cmnd;

    public scsi_data_buffer sdb;

    public Ptr<scsi_data_buffer> prot_sdb;

    public @Unsigned int underflow;

    public @Unsigned int transfersize;

    public @Unsigned int resid_len;

    public @Unsigned int sense_len;

    public String sense_buffer;

    public int flags;

    public @Unsigned long state;

    public @Unsigned int extra_len;

    public String host_scribble;

    public int result;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scsi_prot_operations"
  )
  public enum scsi_prot_operations implements Enum<scsi_prot_operations>, TypedEnum<scsi_prot_operations, java.lang. @Unsigned Integer> {
    /**
     * {@code SCSI_PROT_NORMAL = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SCSI_PROT_NORMAL"
    )
    SCSI_PROT_NORMAL,

    /**
     * {@code SCSI_PROT_READ_INSERT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCSI_PROT_READ_INSERT"
    )
    SCSI_PROT_READ_INSERT,

    /**
     * {@code SCSI_PROT_WRITE_STRIP = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCSI_PROT_WRITE_STRIP"
    )
    SCSI_PROT_WRITE_STRIP,

    /**
     * {@code SCSI_PROT_READ_STRIP = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SCSI_PROT_READ_STRIP"
    )
    SCSI_PROT_READ_STRIP,

    /**
     * {@code SCSI_PROT_WRITE_INSERT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SCSI_PROT_WRITE_INSERT"
    )
    SCSI_PROT_WRITE_INSERT,

    /**
     * {@code SCSI_PROT_READ_PASS = 5}
     */
    @EnumMember(
        value = 5L,
        name = "SCSI_PROT_READ_PASS"
    )
    SCSI_PROT_READ_PASS,

    /**
     * {@code SCSI_PROT_WRITE_PASS = 6}
     */
    @EnumMember(
        value = 6L,
        name = "SCSI_PROT_WRITE_PASS"
    )
    SCSI_PROT_WRITE_PASS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_driver"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_driver extends Struct {
    public device_driver gendrv;

    public Ptr<?> resume;

    public Ptr<?> rescan;

    public Ptr<?> init_command;

    public Ptr<?> uninit_command;

    public Ptr<?> done;

    public Ptr<?> eh_action;

    public Ptr<?> eh_reset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scsi_timeout_action"
  )
  public enum scsi_timeout_action implements Enum<scsi_timeout_action>, TypedEnum<scsi_timeout_action, java.lang. @Unsigned Integer> {
    /**
     * {@code SCSI_EH_DONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SCSI_EH_DONE"
    )
    SCSI_EH_DONE,

    /**
     * {@code SCSI_EH_RESET_TIMER = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCSI_EH_RESET_TIMER"
    )
    SCSI_EH_RESET_TIMER,

    /**
     * {@code SCSI_EH_NOT_HANDLED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCSI_EH_NOT_HANDLED"
    )
    SCSI_EH_NOT_HANDLED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_host_template"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_host_template extends Struct {
    public @Unsigned int cmd_size;

    public Ptr<?> queuecommand;

    public Ptr<?> commit_rqs;

    public Ptr<module> module;

    public String name;

    public Ptr<?> info;

    public Ptr<?> ioctl;

    public Ptr<?> compat_ioctl;

    public Ptr<?> init_cmd_priv;

    public Ptr<?> exit_cmd_priv;

    public Ptr<?> eh_abort_handler;

    public Ptr<?> eh_device_reset_handler;

    public Ptr<?> eh_target_reset_handler;

    public Ptr<?> eh_bus_reset_handler;

    public Ptr<?> eh_host_reset_handler;

    public Ptr<?> sdev_init;

    public Ptr<?> sdev_configure;

    public Ptr<?> sdev_destroy;

    public Ptr<?> target_alloc;

    public Ptr<?> target_destroy;

    public Ptr<?> scan_finished;

    public Ptr<?> scan_start;

    public Ptr<?> change_queue_depth;

    public Ptr<?> map_queues;

    public Ptr<?> mq_poll;

    public Ptr<?> dma_need_drain;

    public Ptr<?> bios_param;

    public Ptr<?> unlock_native_capacity;

    public Ptr<?> show_info;

    public Ptr<?> write_info;

    public Ptr<?> eh_timed_out;

    public Ptr<?> eh_should_retry_cmd;

    public Ptr<?> host_reset;

    public String proc_name;

    public int can_queue;

    public int this_id;

    public @Unsigned short sg_tablesize;

    public @Unsigned short sg_prot_tablesize;

    public @Unsigned int max_sectors;

    public @Unsigned int max_segment_size;

    public @Unsigned int dma_alignment;

    public @Unsigned long dma_boundary;

    public @Unsigned long virt_boundary_mask;

    public short cmd_per_lun;

    public boolean tag_alloc_policy_rr;

    public @Unsigned int track_queue_depth;

    public @Unsigned int supported_mode;

    public @Unsigned int emulated;

    public @Unsigned int skip_settle_delay;

    public @Unsigned int no_write_same;

    public @Unsigned int host_tagset;

    public @Unsigned int queuecommand_may_block;

    public @Unsigned int max_host_blocked;

    public Ptr<Ptr<attribute_group>> shost_groups;

    public Ptr<Ptr<attribute_group>> sdev_groups;

    public @Unsigned long vendor_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scsi_host_state"
  )
  public enum scsi_host_state implements Enum<scsi_host_state>, TypedEnum<scsi_host_state, java.lang. @Unsigned Integer> {
    /**
     * {@code SHOST_CREATED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SHOST_CREATED"
    )
    SHOST_CREATED,

    /**
     * {@code SHOST_RUNNING = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SHOST_RUNNING"
    )
    SHOST_RUNNING,

    /**
     * {@code SHOST_CANCEL = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SHOST_CANCEL"
    )
    SHOST_CANCEL,

    /**
     * {@code SHOST_DEL = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SHOST_DEL"
    )
    SHOST_DEL,

    /**
     * {@code SHOST_RECOVERY = 5}
     */
    @EnumMember(
        value = 5L,
        name = "SHOST_RECOVERY"
    )
    SHOST_RECOVERY,

    /**
     * {@code SHOST_CANCEL_RECOVERY = 6}
     */
    @EnumMember(
        value = 6L,
        name = "SHOST_CANCEL_RECOVERY"
    )
    SHOST_CANCEL_RECOVERY,

    /**
     * {@code SHOST_DEL_RECOVERY = 7}
     */
    @EnumMember(
        value = 7L,
        name = "SHOST_DEL_RECOVERY"
    )
    SHOST_DEL_RECOVERY
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scsi_vpd_parameters"
  )
  public enum scsi_vpd_parameters implements Enum<scsi_vpd_parameters>, TypedEnum<scsi_vpd_parameters, java.lang. @Unsigned Integer> {
    /**
     * {@code SCSI_VPD_HEADER_SIZE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SCSI_VPD_HEADER_SIZE"
    )
    SCSI_VPD_HEADER_SIZE,

    /**
     * {@code SCSI_VPD_LIST_SIZE = 36}
     */
    @EnumMember(
        value = 36L,
        name = "SCSI_VPD_LIST_SIZE"
    )
    SCSI_VPD_LIST_SIZE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_transport_template"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_transport_template extends Struct {
    public transport_container host_attrs;

    public transport_container target_attrs;

    public transport_container device_attrs;

    public Ptr<?> user_scan;

    public int device_size;

    public int device_private_offset;

    public int target_size;

    public int target_private_offset;

    public int host_size;

    public @Unsigned int create_work_queue;

    public Ptr<?> eh_strategy_handler;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_host_busy_iter_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_host_busy_iter_data extends Struct {
    public Ptr<?> fn;

    public Ptr<?> priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scsi_msg_byte"
  )
  public enum scsi_msg_byte implements Enum<scsi_msg_byte>, TypedEnum<scsi_msg_byte, java.lang. @Unsigned Integer> {
    /**
     * {@code COMMAND_COMPLETE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "COMMAND_COMPLETE"
    )
    COMMAND_COMPLETE,

    /**
     * {@code EXTENDED_MESSAGE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "EXTENDED_MESSAGE"
    )
    EXTENDED_MESSAGE,

    /**
     * {@code SAVE_POINTERS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SAVE_POINTERS"
    )
    SAVE_POINTERS,

    /**
     * {@code RESTORE_POINTERS = 3}
     */
    @EnumMember(
        value = 3L,
        name = "RESTORE_POINTERS"
    )
    RESTORE_POINTERS,

    /**
     * {@code DISCONNECT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DISCONNECT"
    )
    DISCONNECT,

    /**
     * {@code INITIATOR_ERROR = 5}
     */
    @EnumMember(
        value = 5L,
        name = "INITIATOR_ERROR"
    )
    INITIATOR_ERROR,

    /**
     * {@code ABORT_TASK_SET = 6}
     */
    @EnumMember(
        value = 6L,
        name = "ABORT_TASK_SET"
    )
    ABORT_TASK_SET,

    /**
     * {@code MESSAGE_REJECT = 7}
     */
    @EnumMember(
        value = 7L,
        name = "MESSAGE_REJECT"
    )
    MESSAGE_REJECT,

    /**
     * {@code NOP = 8}
     */
    @EnumMember(
        value = 8L,
        name = "NOP"
    )
    NOP,

    /**
     * {@code MSG_PARITY_ERROR = 9}
     */
    @EnumMember(
        value = 9L,
        name = "MSG_PARITY_ERROR"
    )
    MSG_PARITY_ERROR,

    /**
     * {@code LINKED_CMD_COMPLETE = 10}
     */
    @EnumMember(
        value = 10L,
        name = "LINKED_CMD_COMPLETE"
    )
    LINKED_CMD_COMPLETE,

    /**
     * {@code LINKED_FLG_CMD_COMPLETE = 11}
     */
    @EnumMember(
        value = 11L,
        name = "LINKED_FLG_CMD_COMPLETE"
    )
    LINKED_FLG_CMD_COMPLETE,

    /**
     * {@code TARGET_RESET = 12}
     */
    @EnumMember(
        value = 12L,
        name = "TARGET_RESET"
    )
    TARGET_RESET,

    /**
     * {@code ABORT_TASK = 13}
     */
    @EnumMember(
        value = 13L,
        name = "ABORT_TASK"
    )
    ABORT_TASK,

    /**
     * {@code CLEAR_TASK_SET = 14}
     */
    @EnumMember(
        value = 14L,
        name = "CLEAR_TASK_SET"
    )
    CLEAR_TASK_SET,

    /**
     * {@code INITIATE_RECOVERY = 15}
     */
    @EnumMember(
        value = 15L,
        name = "INITIATE_RECOVERY"
    )
    INITIATE_RECOVERY,

    /**
     * {@code RELEASE_RECOVERY = 16}
     */
    @EnumMember(
        value = 16L,
        name = "RELEASE_RECOVERY"
    )
    RELEASE_RECOVERY,

    /**
     * {@code TERMINATE_IO_PROC = 17}
     */
    @EnumMember(
        value = 17L,
        name = "TERMINATE_IO_PROC"
    )
    TERMINATE_IO_PROC,

    /**
     * {@code CLEAR_ACA = 22}
     */
    @EnumMember(
        value = 22L,
        name = "CLEAR_ACA"
    )
    CLEAR_ACA,

    /**
     * {@code LOGICAL_UNIT_RESET = 23}
     */
    @EnumMember(
        value = 23L,
        name = "LOGICAL_UNIT_RESET"
    )
    LOGICAL_UNIT_RESET,

    /**
     * {@code SIMPLE_QUEUE_TAG = 32}
     */
    @EnumMember(
        value = 32L,
        name = "SIMPLE_QUEUE_TAG"
    )
    SIMPLE_QUEUE_TAG,

    /**
     * {@code HEAD_OF_QUEUE_TAG = 33}
     */
    @EnumMember(
        value = 33L,
        name = "HEAD_OF_QUEUE_TAG"
    )
    HEAD_OF_QUEUE_TAG,

    /**
     * {@code ORDERED_QUEUE_TAG = 34}
     */
    @EnumMember(
        value = 34L,
        name = "ORDERED_QUEUE_TAG"
    )
    ORDERED_QUEUE_TAG,

    /**
     * {@code IGNORE_WIDE_RESIDUE = 35}
     */
    @EnumMember(
        value = 35L,
        name = "IGNORE_WIDE_RESIDUE"
    )
    IGNORE_WIDE_RESIDUE,

    /**
     * {@code ACA = 36}
     */
    @EnumMember(
        value = 36L,
        name = "ACA"
    )
    ACA,

    /**
     * {@code QAS_REQUEST = 85}
     */
    @EnumMember(
        value = 85L,
        name = "QAS_REQUEST"
    )
    QAS_REQUEST,

    /**
     * {@code BUS_DEVICE_RESET = 12}
     */
    @EnumMember(
        value = 12L,
        name = "BUS_DEVICE_RESET"
    )
    BUS_DEVICE_RESET,

    /**
     * {@code ABORT = 6}
     */
    @EnumMember(
        value = 6L,
        name = "ABORT"
    )
    ABORT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_ioctl_command"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_ioctl_command extends Struct {
    public @Unsigned int inlen;

    public @Unsigned int outlen;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_idlun"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_idlun extends Struct {
    public @Unsigned int dev_id;

    public @Unsigned int host_unique_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_device_handler"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_device_handler extends Struct {
    public list_head list;

    public Ptr<module> module;

    public String name;

    public Ptr<?> check_sense;

    public Ptr<?> attach;

    public Ptr<?> detach;

    public Ptr<?> activate;

    public Ptr<?> prep_fn;

    public Ptr<?> set_params;

    public Ptr<?> rescan;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_eh_save"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_eh_save extends Struct {
    public int result;

    public @Unsigned int resid_len;

    public int eh_eflags;

    public dma_data_direction data_direction;

    public @Unsigned int underflow;

    public char cmd_len;

    public char prot_op;

    public char @Size(32) [] cmnd;

    public scsi_data_buffer sdb;

    public scatterlist sense_sgl;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scsi_ml_status"
  )
  public enum scsi_ml_status implements Enum<scsi_ml_status>, TypedEnum<scsi_ml_status, java.lang. @Unsigned Integer> {
    /**
     * {@code SCSIML_STAT_OK = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SCSIML_STAT_OK"
    )
    SCSIML_STAT_OK,

    /**
     * {@code SCSIML_STAT_RESV_CONFLICT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCSIML_STAT_RESV_CONFLICT"
    )
    SCSIML_STAT_RESV_CONFLICT,

    /**
     * {@code SCSIML_STAT_NOSPC = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCSIML_STAT_NOSPC"
    )
    SCSIML_STAT_NOSPC,

    /**
     * {@code SCSIML_STAT_MED_ERROR = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SCSIML_STAT_MED_ERROR"
    )
    SCSIML_STAT_MED_ERROR,

    /**
     * {@code SCSIML_STAT_TGT_FAILURE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SCSIML_STAT_TGT_FAILURE"
    )
    SCSIML_STAT_TGT_FAILURE,

    /**
     * {@code SCSIML_STAT_DL_TIMEOUT = 5}
     */
    @EnumMember(
        value = 5L,
        name = "SCSIML_STAT_DL_TIMEOUT"
    )
    SCSIML_STAT_DL_TIMEOUT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_event"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_event extends Struct {
    public scsi_device_event evt_type;

    public list_head node;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scsi_host_prot_capabilities"
  )
  public enum scsi_host_prot_capabilities implements Enum<scsi_host_prot_capabilities>, TypedEnum<scsi_host_prot_capabilities, java.lang. @Unsigned Integer> {
    /**
     * {@code SHOST_DIF_TYPE1_PROTECTION = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SHOST_DIF_TYPE1_PROTECTION"
    )
    SHOST_DIF_TYPE1_PROTECTION,

    /**
     * {@code SHOST_DIF_TYPE2_PROTECTION = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SHOST_DIF_TYPE2_PROTECTION"
    )
    SHOST_DIF_TYPE2_PROTECTION,

    /**
     * {@code SHOST_DIF_TYPE3_PROTECTION = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SHOST_DIF_TYPE3_PROTECTION"
    )
    SHOST_DIF_TYPE3_PROTECTION,

    /**
     * {@code SHOST_DIX_TYPE0_PROTECTION = 8}
     */
    @EnumMember(
        value = 8L,
        name = "SHOST_DIX_TYPE0_PROTECTION"
    )
    SHOST_DIX_TYPE0_PROTECTION,

    /**
     * {@code SHOST_DIX_TYPE1_PROTECTION = 16}
     */
    @EnumMember(
        value = 16L,
        name = "SHOST_DIX_TYPE1_PROTECTION"
    )
    SHOST_DIX_TYPE1_PROTECTION,

    /**
     * {@code SHOST_DIX_TYPE2_PROTECTION = 32}
     */
    @EnumMember(
        value = 32L,
        name = "SHOST_DIX_TYPE2_PROTECTION"
    )
    SHOST_DIX_TYPE2_PROTECTION,

    /**
     * {@code SHOST_DIX_TYPE3_PROTECTION = 64}
     */
    @EnumMember(
        value = 64L,
        name = "SHOST_DIX_TYPE3_PROTECTION"
    )
    SHOST_DIX_TYPE3_PROTECTION
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_lun"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_lun extends Struct {
    public char @Size(8) [] scsi_lun;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scsi_timeouts"
  )
  public enum scsi_timeouts implements Enum<scsi_timeouts>, TypedEnum<scsi_timeouts, java.lang. @Unsigned Integer> {
    /**
     * {@code SCSI_DEFAULT_EH_TIMEOUT = 10000}
     */
    @EnumMember(
        value = 10000L,
        name = "SCSI_DEFAULT_EH_TIMEOUT"
    )
    SCSI_DEFAULT_EH_TIMEOUT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scsi_scan_mode"
  )
  public enum scsi_scan_mode implements Enum<scsi_scan_mode>, TypedEnum<scsi_scan_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code SCSI_SCAN_INITIAL = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SCSI_SCAN_INITIAL"
    )
    SCSI_SCAN_INITIAL,

    /**
     * {@code SCSI_SCAN_RESCAN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCSI_SCAN_RESCAN"
    )
    SCSI_SCAN_RESCAN,

    /**
     * {@code SCSI_SCAN_MANUAL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCSI_SCAN_MANUAL"
    )
    SCSI_SCAN_MANUAL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scsi_devinfo_key"
  )
  public enum scsi_devinfo_key implements Enum<scsi_devinfo_key>, TypedEnum<scsi_devinfo_key, java.lang. @Unsigned Integer> {
    /**
     * {@code SCSI_DEVINFO_GLOBAL = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SCSI_DEVINFO_GLOBAL"
    )
    SCSI_DEVINFO_GLOBAL,

    /**
     * {@code SCSI_DEVINFO_SPI = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCSI_DEVINFO_SPI"
    )
    SCSI_DEVINFO_SPI
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_dev_info_list"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_dev_info_list extends Struct {
    public list_head dev_info_list;

    public char @Size(8) [] vendor;

    public char @Size(16) [] model;

    public @Unsigned @OriginalName("blist_flags_t") long flags;

    public @Unsigned int compatible;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_dev_info_list_table"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_dev_info_list_table extends Struct {
    public list_head node;

    public list_head scsi_dev_info_list;

    public String name;

    public int key;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_nl_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_nl_hdr extends Struct {
    public char version;

    public char transport;

    public @Unsigned short magic;

    public @Unsigned short msgtype;

    public @Unsigned short msglen;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_proc_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_proc_entry extends Struct {
    public list_head entry;

    public Ptr<scsi_host_template> sht;

    public Ptr<proc_dir_entry> proc_dir;

    public @Unsigned int present;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_varlen_cdb_hdr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_varlen_cdb_hdr extends Struct {
    public char opcode;

    public char control;

    public char @Size(5) [] misc;

    public char additional_cdb_length;

    public @Unsigned @OriginalName("__be16") short service_action;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_dh_blist"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_dh_blist extends Struct {
    public String vendor;

    public String model;

    public String driver;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scsi_pr_type"
  )
  public enum scsi_pr_type implements Enum<scsi_pr_type>, TypedEnum<scsi_pr_type, java.lang. @Unsigned Integer> {
    /**
     * {@code SCSI_PR_WRITE_EXCLUSIVE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCSI_PR_WRITE_EXCLUSIVE"
    )
    SCSI_PR_WRITE_EXCLUSIVE,

    /**
     * {@code SCSI_PR_EXCLUSIVE_ACCESS = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SCSI_PR_EXCLUSIVE_ACCESS"
    )
    SCSI_PR_EXCLUSIVE_ACCESS,

    /**
     * {@code SCSI_PR_WRITE_EXCLUSIVE_REG_ONLY = 5}
     */
    @EnumMember(
        value = 5L,
        name = "SCSI_PR_WRITE_EXCLUSIVE_REG_ONLY"
    )
    SCSI_PR_WRITE_EXCLUSIVE_REG_ONLY,

    /**
     * {@code SCSI_PR_EXCLUSIVE_ACCESS_REG_ONLY = 6}
     */
    @EnumMember(
        value = 6L,
        name = "SCSI_PR_EXCLUSIVE_ACCESS_REG_ONLY"
    )
    SCSI_PR_EXCLUSIVE_ACCESS_REG_ONLY,

    /**
     * {@code SCSI_PR_WRITE_EXCLUSIVE_ALL_REGS = 7}
     */
    @EnumMember(
        value = 7L,
        name = "SCSI_PR_WRITE_EXCLUSIVE_ALL_REGS"
    )
    SCSI_PR_WRITE_EXCLUSIVE_ALL_REGS,

    /**
     * {@code SCSI_PR_EXCLUSIVE_ACCESS_ALL_REGS = 8}
     */
    @EnumMember(
        value = 8L,
        name = "SCSI_PR_EXCLUSIVE_ACCESS_ALL_REGS"
    )
    SCSI_PR_EXCLUSIVE_ACCESS_ALL_REGS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scsi_host_guard_type"
  )
  public enum scsi_host_guard_type implements Enum<scsi_host_guard_type>, TypedEnum<scsi_host_guard_type, java.lang. @Unsigned Integer> {
    /**
     * {@code SHOST_DIX_GUARD_CRC = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SHOST_DIX_GUARD_CRC"
    )
    SHOST_DIX_GUARD_CRC,

    /**
     * {@code SHOST_DIX_GUARD_IP = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SHOST_DIX_GUARD_IP"
    )
    SHOST_DIX_GUARD_IP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_io_group_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_io_group_descriptor extends Struct {
    public char ic_enable;

    public char cs_enble;

    public char st_enble;

    public char reserved1;

    public char io_advice_hints_mode;

    public char @Size(3) [] reserved2;

    public char lbm_descriptor_type;

    public char rlbsr;

    public char reserved3;

    public char acdlu;

    public char @Size(2) [] params;

    public char reserved4;

    public char @Size(8) [] reserved5;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_stream_status"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_stream_status extends Struct {
    public char reserved1;

    public char perm;

    public char reserved2;

    public @Unsigned @OriginalName("__be16") short stream_identifier;

    public char rel_lifetime;

    public char reserved3;

    public char @Size(3) [] reserved4;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_stream_status_header"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_stream_status_header extends Struct {
    public @Unsigned @OriginalName("__be32") int len;

    public @Unsigned short reserved;

    public @Unsigned @OriginalName("__be16") short number_of_open_streams;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scsi_prot_flags"
  )
  public enum scsi_prot_flags implements Enum<scsi_prot_flags>, TypedEnum<scsi_prot_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code SCSI_PROT_TRANSFER_PI = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCSI_PROT_TRANSFER_PI"
    )
    SCSI_PROT_TRANSFER_PI,

    /**
     * {@code SCSI_PROT_GUARD_CHECK = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCSI_PROT_GUARD_CHECK"
    )
    SCSI_PROT_GUARD_CHECK,

    /**
     * {@code SCSI_PROT_REF_CHECK = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SCSI_PROT_REF_CHECK"
    )
    SCSI_PROT_REF_CHECK,

    /**
     * {@code SCSI_PROT_REF_INCREMENT = 8}
     */
    @EnumMember(
        value = 8L,
        name = "SCSI_PROT_REF_INCREMENT"
    )
    SCSI_PROT_REF_INCREMENT,

    /**
     * {@code SCSI_PROT_IP_CHECKSUM = 16}
     */
    @EnumMember(
        value = 16L,
        name = "SCSI_PROT_IP_CHECKSUM"
    )
    SCSI_PROT_IP_CHECKSUM
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_disk"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_disk extends Struct {
    public Ptr<scsi_device> device;

    public device disk_dev;

    public Ptr<gendisk> disk;

    public Ptr<opal_dev> opal_dev;

    public zoned_disk_info early_zone_info;

    public zoned_disk_info zone_info;

    public @Unsigned int zones_optimal_open;

    public @Unsigned int zones_optimal_nonseq;

    public @Unsigned int zones_max_open;

    public @Unsigned int zone_starting_lba_gran;

    public atomic_t openers;

    public @Unsigned @OriginalName("sector_t") long capacity;

    public int max_retries;

    public @Unsigned int min_xfer_blocks;

    public @Unsigned int max_xfer_blocks;

    public @Unsigned int opt_xfer_blocks;

    public @Unsigned int max_ws_blocks;

    public @Unsigned int max_unmap_blocks;

    public @Unsigned int unmap_granularity;

    public @Unsigned int unmap_alignment;

    public @Unsigned int max_atomic;

    public @Unsigned int atomic_alignment;

    public @Unsigned int atomic_granularity;

    public @Unsigned int max_atomic_with_boundary;

    public @Unsigned int max_atomic_boundary;

    public @Unsigned int index;

    public @Unsigned int physical_block_size;

    public @Unsigned int max_medium_access_timeouts;

    public @Unsigned int medium_access_timed_out;

    public @Unsigned short permanent_stream_count;

    public char media_present;

    public char write_prot;

    public char protection_type;

    public char provisioning_mode;

    public char zeroing_mode;

    public char nr_actuators;

    public boolean suspended;

    public @Unsigned int ATO;

    public @Unsigned int cache_override;

    public @Unsigned int WCE;

    public @Unsigned int RCD;

    public @Unsigned int DPOFUA;

    public @Unsigned int first_scan;

    public @Unsigned int lbpme;

    public @Unsigned int lbprz;

    public @Unsigned int lbpu;

    public @Unsigned int lbpws;

    public @Unsigned int lbpws10;

    public @Unsigned int lbpvpd;

    public @Unsigned int ws10;

    public @Unsigned int ws16;

    public @Unsigned int rc_basis;

    public @Unsigned int zoned;

    public @Unsigned int urswrz;

    public @Unsigned int security;

    public @Unsigned int ignore_medium_access_errors;

    public @Unsigned int rscs;

    public @Unsigned int use_atomic_write_boundary;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scsi_cd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scsi_cd extends Struct {
    public @Unsigned int capacity;

    public Ptr<scsi_device> device;

    public @Unsigned int vendor;

    public @Unsigned long ms_offset;

    public @Unsigned int writeable;

    public @Unsigned int use;

    public @Unsigned int xa_flag;

    public @Unsigned int readcd_known;

    public @Unsigned int readcd_cdda;

    public @Unsigned int media_present;

    public int tur_mismatch;

    public boolean tur_changed;

    public boolean get_event_changed;

    public boolean ignore_get_event;

    public cdrom_device_info cdi;

    public mutex lock;

    public Ptr<gendisk> disk;
  }
}
