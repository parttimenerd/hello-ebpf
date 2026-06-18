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
import static me.bechberger.ebpf.runtime.ScsiDefinitions.*;
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
 * Generated class for BPF runtime types that start with perf
 */
@java.lang.SuppressWarnings("unused")
public final class PerfDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ___perf_sw_event(@Unsigned int event_id, @Unsigned long nr, Ptr<pt_regs> regs,
      @Unsigned long addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __perf_addr_filters_adjust(Ptr<perf_event> event, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __perf_cgroup_move(Ptr<?> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __perf_event__output_id_sample(Ptr<perf_output_handle> handle,
      Ptr<perf_sample_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __perf_event_account_interrupt(Ptr<perf_event> event, int throttle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __perf_event_enable(Ptr<perf_event> event, Ptr<perf_cpu_context> cpuctx,
      Ptr<perf_event_context> ctx, Ptr<?> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __perf_event_exit_context(Ptr<?> __info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __perf_event_header__init_id(Ptr<perf_sample_data> data, Ptr<perf_event> event,
      @Unsigned long sample_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __perf_event_output_stop(Ptr<perf_event> event, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __perf_event_overflow(Ptr<perf_event> event, int throttle,
      Ptr<perf_sample_data> data, Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __perf_event_period(Ptr<perf_event> event, Ptr<perf_cpu_context> cpuctx,
      Ptr<perf_event_context> ctx, Ptr<?> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __perf_event_read(Ptr<?> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __perf_event_read_cpu(Ptr<perf_event> event, int event_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __perf_event_read_size(@Unsigned long read_format, int nr_siblings) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long __perf_event_read_value(Ptr<perf_event> event,
      Ptr<java.lang. @Unsigned Long> enabled, Ptr<java.lang. @Unsigned Long> running) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __perf_event_set_bpf_prog(Ptr<perf_event> event, Ptr<bpf_prog> prog,
      @Unsigned long bpf_cookie) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __perf_event_stop(Ptr<?> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __perf_event_task_sched_in(Ptr<task_struct> prev, Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __perf_event_task_sched_out(Ptr<task_struct> task, Ptr<task_struct> next) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __perf_install_in_context(Ptr<?> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __perf_pmu_install_event(Ptr<pmu> pmu, Ptr<perf_event_context> ctx, int cpu,
      Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __perf_pmu_output_stop(Ptr<?> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __perf_read_group_add(Ptr<perf_event> leader, @Unsigned long read_format,
      Ptr<java.lang. @Unsigned Long> values) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __perf_remove_from_context(Ptr<perf_event> event, Ptr<perf_cpu_context> cpuctx,
      Ptr<perf_event_context> ctx, Ptr<?> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __perf_sw_event(@Unsigned int event_id, @Unsigned long nr, Ptr<pt_regs> regs,
      @Unsigned long addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __perf_tp_event_target_task(@Unsigned long count, Ptr<?> record,
      Ptr<pt_regs> regs, Ptr<perf_sample_data> data, Ptr<perf_raw_record> raw,
      Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void _perf_event_disable(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void _perf_event_enable(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int _perf_event_period(Ptr<perf_event> event, @Unsigned long value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void _perf_event_reset(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long _perf_ioctl(Ptr<perf_event> event, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean perf_addr_filter_vma_adjust(Ptr<perf_addr_filter> filter,
      Ptr<vm_area_struct> vma, Ptr<perf_addr_filter_range> fr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_addr_filters_splice(Ptr<perf_event> event, Ptr<list_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_adjust_freq_unthr_context(Ptr<perf_event_context> ctx,
      boolean unthrottle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_adjust_freq_unthr_events(Ptr<list_head> event_list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_adjust_period(Ptr<perf_event> event, @Unsigned long nsec,
      @Unsigned long count, boolean disable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_allow_kernel() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_amd_brs_lopwr_cb(boolean lopwr_in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long perf_arch_guest_misc_flags(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long perf_arch_instruction_pointer(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long perf_arch_misc_flags(Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_assign_events(Ptr<Ptr<event_constraint>> constraints, int n, int wmin,
      int wmax, int gpmax, Ptr<java.lang.Integer> assign) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> perf_aux_output_begin(Ptr<perf_output_handle> handle,
      Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_aux_output_end(Ptr<perf_output_handle> handle, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_aux_output_flag(Ptr<perf_output_handle> handle, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_aux_output_skip(Ptr<perf_output_handle> handle, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_bp_event(Ptr<perf_event> bp, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_call_bpf_enter(Ptr<trace_event_call> call, Ptr<pt_regs> regs,
      Ptr<syscall_metadata> sys_data, Ptr<syscall_trace_enter> rec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<perf_callchain_entry> perf_callchain(Ptr<perf_event> event, Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_callchain_kernel(Ptr<perf_callchain_entry_ctx> entry, Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_callchain_user(Ptr<perf_callchain_entry_ctx> entry, Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_cgroup_attach(Ptr<cgroup_taskset> tset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<cgroup_subsys_state> perf_cgroup_css_alloc(
      Ptr<cgroup_subsys_state> parent_css) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_cgroup_css_free(Ptr<cgroup_subsys_state> css) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_cgroup_css_online(Ptr<cgroup_subsys_state> css) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_cgroup_switch(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_check_microcode() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_clear_dirty_counters() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long perf_compat_ioctl(Ptr<file> file, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_copy_attr(Ptr<perf_event_attr> uattr, Ptr<perf_event_attr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<perf_event_context> perf_cpu_task_ctx() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_cpu_time_max_percent_handler((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int perf_cpu_time_max_percent_handler(Ptr<ctl_table> table, int write,
      Ptr<?> buffer, Ptr<java.lang. @Unsigned Long> lenp,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_ctx_disable(Ptr<perf_event_context> ctx, boolean cgroup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_ctx_enable(Ptr<perf_event_context> ctx, boolean cgroup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_ctx_sched_task_cb(Ptr<perf_event_context> ctx, Ptr<task_struct> task,
      boolean sched_in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_ctx_unlock(Ptr<perf_cpu_context> cpuctx, Ptr<perf_event_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_duration_warn(Ptr<irq_work> w) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event__header_size(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event__id_header_size(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event__output_id_sample(Ptr<perf_event> event,
      Ptr<perf_output_handle> handle, Ptr<perf_sample_data> sample) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_account_interrupt(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_addr_filters_apply(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_addr_filters_exec(Ptr<perf_event> event, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_addr_filters_sync(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<perf_event> perf_event_alloc(Ptr<perf_event_attr> attr, int cpu,
      Ptr<task_struct> task, Ptr<perf_event> group_leader, Ptr<perf_event> parent_event,
      @OriginalName("perf_overflow_handler_t") Ptr<?> overflow_handler, Ptr<?> context,
      int cgroup_fd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_alloc_task_data(Ptr<task_struct> child, Ptr<task_struct> parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_attach_bpf_prog(Ptr<perf_event> event, Ptr<bpf_prog> prog,
      @Unsigned long bpf_cookie) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct perf_event_attr*)perf_event_attrs($arg1))")
  public static Ptr<perf_event_attr> perf_event_attrs(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_aux_event(Ptr<perf_event> event, @Unsigned long head,
      @Unsigned long size, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_aux_pause(Ptr<perf_event> event, boolean pause) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_bpf_event(Ptr<bpf_prog> prog, perf_bpf_event_type type,
      @Unsigned short flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_bpf_output(Ptr<perf_event> event, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_cgroup(Ptr<cgroup> cgrp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_cgroup_output(Ptr<perf_event> event, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_clear_cpumask(@Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_comm(Ptr<task_struct> task, boolean exec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_comm_event(Ptr<perf_comm_event> comm_event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_comm_output(Ptr<perf_event> event, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_context_sched_out(Ptr<task_struct> task, Ptr<task_struct> next) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<perf_event> perf_event_create_kernel_counter(Ptr<perf_event_attr> attr, int cpu,
      Ptr<task_struct> task, @OriginalName("perf_overflow_handler_t") Ptr<?> overflow_handler,
      Ptr<?> context) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<perf_event_context> perf_event_ctx_lock_nested(Ptr<perf_event> event,
      int nesting) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_delayed_put(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_detach_bpf_prog(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_disable(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_disable_inatomic(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_disable_local(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_enable(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_enable_on_exec(Ptr<perf_event_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_exec() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_exit_cpu(@Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_exit_cpu_context(int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_exit_task(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_exit_task_context(Ptr<task_struct> task, boolean exit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> perf_event_fd_array_get_ptr(Ptr<bpf_map> map, Ptr<file> map_file, int fd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_fd_array_map_free(Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_fd_array_put_ptr(Ptr<bpf_map> map, Ptr<?> ptr, boolean need_defer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_fd_array_release(Ptr<bpf_map> map, Ptr<file> map_file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_event_for_each_child($arg1, (void (*)(struct perf_event*))$arg2)")
  public static void perf_event_for_each_child(Ptr<perf_event> event, Ptr<?> func) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_fork(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_free_bpf_prog(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_free_task(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<file> perf_event_get(@Unsigned int fd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<perf_event> perf_event_groups_first(Ptr<perf_event_groups> groups, int cpu,
      Ptr<pmu> pmu, Ptr<cgroup> cgrp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_groups_insert(Ptr<perf_event_groups> groups,
      Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<perf_event> perf_event_groups_next(Ptr<perf_event> event, Ptr<pmu> pmu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_header__init_id(Ptr<perf_event_header> header,
      Ptr<perf_sample_data> data, Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_ibs_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_idx_default(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_init_all_cpus() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_init_context(Ptr<task_struct> child, @Unsigned long clone_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_init_cpu(@Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_init_task(Ptr<task_struct> child, @Unsigned long clone_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_itrace_started(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_event_ksymbol($arg1, $arg2, $arg3, $arg4, (const u8*)$arg5)")
  public static void perf_event_ksymbol(@Unsigned short ksym_type, @Unsigned long addr,
      @Unsigned int len, boolean unregister, String sym) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_ksymbol_output(Ptr<perf_event> event, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_event_max_sample_rate_handler((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int perf_event_max_sample_rate_handler(Ptr<ctl_table> table, int write,
      Ptr<?> buffer, Ptr<java.lang. @Unsigned Long> lenp,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_event_max_stack_handler((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int perf_event_max_stack_handler(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_mmap(Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_mmap_event(Ptr<perf_mmap_event> mmap_event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_mmap_output(Ptr<perf_event> event, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long perf_event_mux_interval_ms_show(Ptr<device> dev,
      Ptr<device_attribute> attr, String page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_event_mux_interval_ms_store($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static @OriginalName("ssize_t") long perf_event_mux_interval_ms_store(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_namespaces(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_namespaces_output(Ptr<perf_event> event, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_nmi_handler(@Unsigned int cmd, Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_nop_int(Ptr<perf_event> event, @Unsigned long value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_output(Ptr<perf_event> event, Ptr<perf_sample_data> data,
      Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_output_backward(Ptr<perf_event> event, Ptr<perf_sample_data> data,
      Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_output_forward(Ptr<perf_event> event, Ptr<perf_sample_data> data,
      Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_overflow(Ptr<perf_event> event, Ptr<perf_sample_data> data,
      Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_parse_addr_filter(Ptr<perf_event> event, String fstr,
      Ptr<list_head> filters) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long perf_event_pause(Ptr<perf_event> event, boolean reset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_period(Ptr<perf_event> event, @Unsigned long value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_print_debug() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_query_prog_array(Ptr<perf_event> event, Ptr<?> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_read(Ptr<perf_event> event, boolean group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_read_event(Ptr<perf_event> event, Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_read_local(Ptr<perf_event> event,
      Ptr<java.lang. @Unsigned Long> value, Ptr<java.lang. @Unsigned Long> enabled,
      Ptr<java.lang. @Unsigned Long> running) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long perf_event_read_value(Ptr<perf_event> event,
      Ptr<java.lang. @Unsigned Long> enabled, Ptr<java.lang. @Unsigned Long> running) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_refresh(Ptr<perf_event> event, int refresh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_release_kernel(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_sched_in(Ptr<perf_cpu_context> cpuctx, Ptr<perf_event_context> ctx,
      Ptr<pmu> pmu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_set_bpf_prog(Ptr<perf_event> event, Ptr<bpf_prog> prog,
      @Unsigned long bpf_cookie) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_set_output(Ptr<perf_event> event, Ptr<perf_event> output_event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_setup_cpumask(@Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_stop(Ptr<perf_event> event, int restart) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_switch_output(Ptr<perf_event> event, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_sysfs_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long perf_event_sysfs_show(Ptr<device> dev,
      Ptr<device_attribute> attr, String page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_task(Ptr<task_struct> task, Ptr<perf_event_context> task_ctx,
      int _new) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_task_disable() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_event_task_enable() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_task_output(Ptr<perf_event> event, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_task_tick() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_event_text_poke((const void*)$arg1, (const void*)$arg2, $arg3, (const void*)$arg4, $arg5)")
  public static void perf_event_text_poke(Ptr<?> addr, Ptr<?> old_bytes, @Unsigned long old_len,
      Ptr<?> new_bytes, @Unsigned long new_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_text_poke_output(Ptr<perf_event> event, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_unthrottle_group(Ptr<perf_event> event, boolean skip_start_event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_update_time(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_update_userpage(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_event_wakeup(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_events_lapic_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_exclude_event(Ptr<perf_event> event, Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_fasync(int fd, Ptr<file> filp, int on) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_fill_ns_link_info($arg1, $arg2, (const struct proc_ns_operations*)$arg3)")
  public static void perf_fill_ns_link_info(Ptr<perf_ns_link_info> ns_link_info,
      Ptr<task_struct> task, Ptr<proc_ns_operations> ns_ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_ftrace_event_register(Ptr<trace_event_call> call, trace_reg type,
      Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_ftrace_function_call(@Unsigned long ip, @Unsigned long parent_ip,
      Ptr<ftrace_ops> ops, Ptr<ftrace_regs> fregs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> perf_get_aux(Ptr<perf_output_handle> handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_get_aux_event(Ptr<perf_event> event, Ptr<perf_event> group_leader) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct perf_event*)perf_get_event($arg1))")
  public static Ptr<perf_event> perf_get_event(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long perf_get_hw_event_config(int hw_event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long perf_get_page_size(@Unsigned long addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long perf_get_pgtable_size(Ptr<mm_struct> mm, @Unsigned long addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_get_regs_user(Ptr<perf_regs> regs_user, Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_get_x86_pmu_capability(Ptr<x86_pmu_capability> cap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_group_attach(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_group_detach(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<perf_guest_switch_msr> perf_guest_get_msrs(Ptr<java.lang.Integer> nr,
      Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_ibs_add(Ptr<perf_event> event, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_ibs_check_period(Ptr<perf_event> event, @Unsigned long value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_ibs_del(Ptr<perf_event> event, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_ibs_event_update(Ptr<perf_ibs> perf_ibs, Ptr<perf_event> event,
      Ptr<java.lang. @Unsigned Long> config) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_ibs_handle_irq(Ptr<perf_ibs> perf_ibs, Ptr<pt_regs> iregs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_ibs_init(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_ibs_nmi_handler(@Unsigned int cmd, Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_ibs_pmu_init(Ptr<perf_ibs> perf_ibs, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_ibs_read(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_ibs_resume() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_ibs_start(Ptr<perf_event> event, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_ibs_stop(Ptr<perf_event> event, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_ibs_suspend() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_install_in_context(Ptr<perf_event_context> ctx, Ptr<perf_event> event,
      int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long perf_instruction_pointer(Ptr<perf_event> event, Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long perf_ioctl(Ptr<file> file, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_iommu_add(Ptr<perf_event> event, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_iommu_del(Ptr<perf_event> event, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_iommu_event_init(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_iommu_read(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_iommu_start(Ptr<perf_event> event, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_iommu_stop(Ptr<perf_event> event, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_iterate_ctx(Ptr<perf_event_context> ctx, Ptr<?> output, Ptr<?> data,
      boolean all) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_iterate_sb(Ptr<?> output, Ptr<?> data, Ptr<perf_event_context> task_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_kprobe_destroy(Ptr<perf_event> p_event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_kprobe_event_init(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_kprobe_init(Ptr<perf_event> p_event, boolean is_retprobe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<perf_event_context> perf_lock_task_context(Ptr<task_struct> task,
      Ptr<java.lang. @Unsigned Long> flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_log_itrace_start(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_log_lost_samples(Ptr<perf_event> event, @Unsigned long lost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_log_throttle(Ptr<perf_event> event, int enable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long perf_misc_flags(Ptr<perf_event> event, Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_mmap(Ptr<file> file, Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> perf_mmap_alloc_page(int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_mmap_close(Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_mmap_may_split(Ptr<vm_area_struct> vma, @Unsigned long addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_mmap_open(Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int perf_mmap_pfn_mkwrite(Ptr<vm_fault> vmf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<page> perf_mmap_to_page(Ptr<perf_buffer> rb, @Unsigned long pgoff) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long perf_msr_probe(Ptr<perf_msr> msr, int cnt, boolean zero,
      Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static hrtimer_restart perf_mux_hrtimer_handler(Ptr<hrtimer> hr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_mux_hrtimer_restart(Ptr<perf_cpu_pmu_context> cpc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_mux_hrtimer_restart_ipi(Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_output_begin(Ptr<perf_output_handle> handle, Ptr<perf_sample_data> data,
      Ptr<perf_event> event, @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_output_begin_backward(Ptr<perf_output_handle> handle,
      Ptr<perf_sample_data> data, Ptr<perf_event> event, @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_output_begin_forward(Ptr<perf_output_handle> handle,
      Ptr<perf_sample_data> data, Ptr<perf_event> event, @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_output_copy($arg1, (const void*)$arg2, $arg3)")
  public static @Unsigned int perf_output_copy(Ptr<perf_output_handle> handle, Ptr<?> buf,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long perf_output_copy_aux(Ptr<perf_output_handle> aux_handle,
      Ptr<perf_output_handle> handle, @Unsigned long from, @Unsigned long to) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_output_end(Ptr<perf_output_handle> handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_output_put_handle(Ptr<perf_output_handle> handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_output_read(Ptr<perf_output_handle> handle, Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_output_read_group(Ptr<perf_output_handle> handle, Ptr<perf_event> event,
      @Unsigned long enabled, @Unsigned long running) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_output_sample(Ptr<perf_output_handle> handle,
      Ptr<perf_event_header> header, Ptr<perf_sample_data> data, Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_output_sample_regs(Ptr<perf_output_handle> handle, Ptr<pt_regs> regs,
      @Unsigned long mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int perf_output_skip(Ptr<perf_output_handle> handle, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_pending_disable(Ptr<irq_work> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_pending_irq(Ptr<irq_work> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_pending_task(Ptr<callback_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_perm_irq_work_exit(Ptr<trace_event_call> tp_event,
      Ptr<perf_event> p_event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_pmu_cancel_txn(Ptr<pmu> pmu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_pmu_commit_txn(Ptr<pmu> pmu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_pmu_disable(Ptr<pmu> pmu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_pmu_enable(Ptr<pmu> pmu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_pmu_free(Ptr<pmu> pmu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_pmu_migrate_context(Ptr<pmu> pmu, int src_cpu, int dst_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_pmu_nop_int(Ptr<pmu> pmu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_pmu_nop_txn(Ptr<pmu> pmu, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_pmu_nop_void(Ptr<pmu> pmu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_pmu_register($arg1, (const u8*)$arg2, $arg3)")
  public static int perf_pmu_register(Ptr<pmu> _pmu, String name, int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_pmu_resched(Ptr<pmu> pmu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_pmu_sched_task(Ptr<task_struct> prev, Ptr<task_struct> next,
      boolean sched_in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long perf_pmu_snapshot_aux(Ptr<perf_buffer> rb, Ptr<perf_event> event,
      Ptr<perf_output_handle> handle, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_pmu_start_txn(Ptr<pmu> pmu, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_pmu_unregister(Ptr<pmu> pmu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__poll_t") int perf_poll(Ptr<file> file,
      Ptr<poll_table_struct> wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_prepare_header(Ptr<perf_event_header> header, Ptr<perf_sample_data> data,
      Ptr<perf_event> event, Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_prepare_sample(Ptr<perf_sample_data> data, Ptr<perf_event> event,
      Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long perf_read(Ptr<file> file, String buf,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_reboot(Ptr<notifier_block> notifier, @Unsigned long val, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long perf_reg_abi(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_reg_validate(@Unsigned long mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long perf_reg_value(Ptr<pt_regs> regs, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_register_guest_info_callbacks(Ptr<perf_guest_info_callbacks> cbs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_release(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_remove_from_context(Ptr<perf_event> event, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_remove_from_owner(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_report_aux_output_id(Ptr<perf_event> event, @Unsigned long hw_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_restore_debug_store() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean perf_rotate_context(Ptr<perf_cpu_pmu_context> cpc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_sample_event_took(@Unsigned long sample_len_ns) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_sched_cb_dec(Ptr<pmu> pmu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_sched_cb_inc(Ptr<pmu> pmu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_sched_delayed(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_state_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_state_show(Ptr<seq_file> s, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_swevent_add(Ptr<perf_event> event, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_swevent_del(Ptr<perf_event> event, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_swevent_event(Ptr<perf_event> event, @Unsigned long nr,
      Ptr<perf_sample_data> data, Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_swevent_get_recursion_context() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static hrtimer_restart perf_swevent_hrtimer(Ptr<hrtimer> hrtimer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_swevent_init(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_swevent_put_recursion_context(int rctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_swevent_read(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long perf_swevent_set_period(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_swevent_start(Ptr<perf_event> event, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_swevent_stop(Ptr<perf_event> event, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_syscall_enter(Ptr<?> ignore, Ptr<pt_regs> regs, long id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_syscall_exit(Ptr<?> ignore, Ptr<pt_regs> regs, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_tp_event(@Unsigned short event_type, @Unsigned long count, Ptr<?> record,
      int entry_size, Ptr<pt_regs> regs, Ptr<hlist_head> head, int rctx, Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_tp_event_init(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_tp_event_match(Ptr<perf_event> event, Ptr<perf_raw_record> raw,
      Ptr<pt_regs> regs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ack_update_msk(Ptr<?> __data, @Unsigned long data_ack,
      @Unsigned long old_snd_una, @Unsigned long new_snd_una, @Unsigned long new_wnd_end,
      @Unsigned long msk_wnd_end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_trace_add(Ptr<perf_event> p_event, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_aer_event($arg1, (const u8*)$arg2, (const unsigned int)$arg3, (const u8)$arg4, (const u8)$arg5, $arg6)")
  public static void perf_trace_aer_event(Ptr<?> __data, String dev_name, @Unsigned int status,
      char severity, char tlp_header_valid, Ptr<pcie_tlp_log> tlp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_alarm_class(Ptr<?> __data, Ptr<alarm> alarm,
      @OriginalName("ktime_t") long now) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_alarmtimer_suspend(Ptr<?> __data,
      @OriginalName("ktime_t") long expires, int flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_alloc_vmap_area(Ptr<?> __data, @Unsigned long addr,
      @Unsigned long size, @Unsigned long align, @Unsigned long vstart, @Unsigned long vend,
      int failed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_amd_pstate_epp_perf(Ptr<?> __data, @Unsigned int cpu_id,
      char highest_perf, char epp, char min_perf, char max_perf, boolean boost, boolean changed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_amd_pstate_perf(Ptr<?> __data, char min_perf, char target_perf,
      char capacity, @Unsigned long freq, @Unsigned long mperf, @Unsigned long aperf,
      @Unsigned long tsc, @Unsigned int cpu_id, boolean fast_switch) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_arm_event($arg1, (const struct cper_sec_proc_arm*)$arg2, (const u8*)$arg3, (const unsigned int)$arg4, (const u8*)$arg5, (const unsigned int)$arg6, (const u8*)$arg7, (const unsigned int)$arg8, $arg9, $arg10)")
  public static void perf_trace_arm_event(Ptr<?> __data, Ptr<cper_sec_proc_arm> proc,
      Ptr<java.lang.Character> pei_err, @Unsigned int pei_len, Ptr<java.lang.Character> ctx_err,
      @Unsigned int ctx_len, Ptr<java.lang.Character> oem, @Unsigned int oem_len, char sev,
      int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ata_bmdma_status(Ptr<?> __data, Ptr<ata_port> ap,
      @Unsigned int host_stat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ata_eh_action_template(Ptr<?> __data, Ptr<ata_link> link,
      @Unsigned int devno, @Unsigned int eh_action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ata_eh_link_autopsy(Ptr<?> __data, Ptr<ata_device> dev,
      @Unsigned int eh_action, @Unsigned int eh_err_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ata_eh_link_autopsy_qc(Ptr<?> __data, Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_ata_exec_command_template($arg1, $arg2, (const struct ata_taskfile*)$arg3, $arg4)")
  public static void perf_trace_ata_exec_command_template(Ptr<?> __data, Ptr<ata_port> ap,
      Ptr<ata_taskfile> tf, @Unsigned int tag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ata_link_reset_begin_template(Ptr<?> __data, Ptr<ata_link> link,
      Ptr<java.lang. @Unsigned Integer> _class, @Unsigned long deadline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ata_link_reset_end_template(Ptr<?> __data, Ptr<ata_link> link,
      Ptr<java.lang. @Unsigned Integer> _class, int rc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ata_port_eh_begin_template(Ptr<?> __data, Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ata_qc_complete_template(Ptr<?> __data, Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ata_qc_issue_template(Ptr<?> __data, Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ata_sff_hsm_template(Ptr<?> __data, Ptr<ata_queued_cmd> qc,
      char status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ata_sff_template(Ptr<?> __data, Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_ata_tf_load($arg1, $arg2, (const struct ata_taskfile*)$arg3)")
  public static void perf_trace_ata_tf_load(Ptr<?> __data, Ptr<ata_port> ap, Ptr<ata_taskfile> tf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ata_transfer_data_template(Ptr<?> __data, Ptr<ata_queued_cmd> qc,
      @Unsigned int offset, @Unsigned int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_balance_dirty_pages(Ptr<?> __data, Ptr<bdi_writeback> wb,
      Ptr<dirty_throttle_control> dtc, @Unsigned long dirty_ratelimit,
      @Unsigned long task_ratelimit, @Unsigned long dirtied, @Unsigned long period, long pause,
      @Unsigned long start_time) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_bdi_dirty_ratelimit(Ptr<?> __data, Ptr<bdi_writeback> wb,
      @Unsigned long dirty_rate, @Unsigned long task_ratelimit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_blkdev_zone_mgmt(Ptr<?> __data, Ptr<bio> bio,
      @Unsigned @OriginalName("sector_t") long nr_sectors) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_block_bio(Ptr<?> __data, Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_block_bio_complete(Ptr<?> __data, Ptr<request_queue> q,
      Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_block_bio_remap(Ptr<?> __data, Ptr<bio> bio,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("sector_t") long from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_block_buffer(Ptr<?> __data, Ptr<buffer_head> bh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_block_plug(Ptr<?> __data, Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_block_rq(Ptr<?> __data, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_block_rq_completion(Ptr<?> __data, Ptr<request> rq,
      @OriginalName("blk_status_t") char error, @Unsigned int nr_bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_block_rq_remap(Ptr<?> __data, Ptr<request> rq,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("sector_t") long from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_block_rq_requeue(Ptr<?> __data, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_block_split(Ptr<?> __data, Ptr<bio> bio, @Unsigned int new_sector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_block_unplug(Ptr<?> __data, Ptr<request_queue> q,
      @Unsigned int depth, boolean explicit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_block_zwplug(Ptr<?> __data, Ptr<request_queue> q, @Unsigned int zno,
      @Unsigned @OriginalName("sector_t") long sector, @Unsigned int nr_sectors) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_bpf_test_finish(Ptr<?> __data, Ptr<java.lang.Integer> err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_bpf_trace_printk($arg1, (const u8*)$arg2)")
  public static void perf_trace_bpf_trace_printk(Ptr<?> __data, String bpf_string) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_bpf_trigger_tp(Ptr<?> __data, int nonce) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_bpf_xdp_link_attach_failed($arg1, (const u8*)$arg2)")
  public static void perf_trace_bpf_xdp_link_attach_failed(Ptr<?> __data, String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_br_fdb_add($arg1, $arg2, $arg3, (const u8*)$arg4, $arg5, $arg6)")
  public static void perf_trace_br_fdb_add(Ptr<?> __data, Ptr<ndmsg> ndm, Ptr<net_device> dev,
      String addr, @Unsigned short vid, @Unsigned short nlh_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_br_fdb_external_learn_add($arg1, $arg2, $arg3, (const u8*)$arg4, $arg5)")
  public static void perf_trace_br_fdb_external_learn_add(Ptr<?> __data, Ptr<net_bridge> br,
      Ptr<net_bridge_port> p, String addr, @Unsigned short vid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_br_fdb_update($arg1, $arg2, $arg3, (const u8*)$arg4, $arg5, $arg6)")
  public static void perf_trace_br_fdb_update(Ptr<?> __data, Ptr<net_bridge> br,
      Ptr<net_bridge_port> source, String addr, @Unsigned short vid, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_br_mdb_full($arg1, (const struct net_device*)$arg2, (const struct br_ip*)$arg3)")
  public static void perf_trace_br_mdb_full(Ptr<?> __data, Ptr<net_device> dev, Ptr<br_ip> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> perf_trace_buf_alloc(int size, Ptr<Ptr<pt_regs>> regs,
      Ptr<java.lang.Integer> rctxp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_buf_update(Ptr<?> record, @Unsigned short type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_cache_tag_flush(Ptr<?> __data, Ptr<cache_tag> tag,
      @Unsigned long start, @Unsigned long end, @Unsigned long addr, @Unsigned long pages,
      @Unsigned long mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_cache_tag_log(Ptr<?> __data, Ptr<cache_tag> tag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_cap_capable($arg1, (const struct cred*)$arg2, $arg3, (const struct user_namespace*)$arg4, $arg5, $arg6)")
  public static void perf_trace_cap_capable(Ptr<?> __data, Ptr<cred> cred,
      Ptr<user_namespace> target_ns, Ptr<user_namespace> capable_ns, int cap, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_cdev_update(Ptr<?> __data, Ptr<thermal_cooling_device> cdev,
      @Unsigned long target) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_cgroup($arg1, $arg2, (const u8*)$arg3)")
  public static void perf_trace_cgroup(Ptr<?> __data, Ptr<cgroup> cgrp, String path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_cgroup_event($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static void perf_trace_cgroup_event(Ptr<?> __data, Ptr<cgroup> cgrp, String path,
      int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_cgroup_migrate($arg1, $arg2, (const u8*)$arg3, $arg4, $arg5)")
  public static void perf_trace_cgroup_migrate(Ptr<?> __data, Ptr<cgroup> dst_cgrp, String path,
      Ptr<task_struct> task, boolean threadgroup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_cgroup_root(Ptr<?> __data, Ptr<cgroup_root> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_cgroup_rstat(Ptr<?> __data, Ptr<cgroup> cgrp, int cpu,
      boolean contended) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_clk(Ptr<?> __data, Ptr<clk_core> core) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_clk_duty_cycle(Ptr<?> __data, Ptr<clk_core> core,
      Ptr<clk_duty> duty) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_clk_parent(Ptr<?> __data, Ptr<clk_core> core,
      Ptr<clk_core> parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_clk_phase(Ptr<?> __data, Ptr<clk_core> core, int phase) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_clk_rate(Ptr<?> __data, Ptr<clk_core> core, @Unsigned long rate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_clk_rate_range(Ptr<?> __data, Ptr<clk_core> core,
      @Unsigned long min, @Unsigned long max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_clk_rate_request(Ptr<?> __data, Ptr<clk_rate_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_cma_alloc_busy_retry($arg1, (const u8*)$arg2, $arg3, (const struct page*)$arg4, $arg5, $arg6)")
  public static void perf_trace_cma_alloc_busy_retry(Ptr<?> __data, String name, @Unsigned long pfn,
      Ptr<page> page, @Unsigned long count, @Unsigned int align) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_cma_alloc_finish($arg1, (const u8*)$arg2, $arg3, (const struct page*)$arg4, $arg5, $arg6, $arg7)")
  public static void perf_trace_cma_alloc_finish(Ptr<?> __data, String name, @Unsigned long pfn,
      Ptr<page> page, @Unsigned long count, @Unsigned int align, int errorno) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_cma_alloc_start($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static void perf_trace_cma_alloc_start(Ptr<?> __data, String name, @Unsigned long count,
      @Unsigned int align) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_cma_release($arg1, (const u8*)$arg2, $arg3, (const struct page*)$arg4, $arg5)")
  public static void perf_trace_cma_release(Ptr<?> __data, String name, @Unsigned long pfn,
      Ptr<page> page, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_compact_retry(Ptr<?> __data, int order, compact_priority priority,
      compact_result result, int retries, int max_retries, boolean ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_console($arg1, (const u8*)$arg2, $arg3)")
  public static void perf_trace_console(Ptr<?> __data, String text, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_consume_skb(Ptr<?> __data, Ptr<sk_buff> skb, Ptr<?> location) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_contention_begin(Ptr<?> __data, Ptr<?> lock, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_contention_end(Ptr<?> __data, Ptr<?> lock, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_context_tracking_user(Ptr<?> __data, int dummy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_cpu(Ptr<?> __data, @Unsigned int state, @Unsigned int cpu_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_cpu_frequency_limits(Ptr<?> __data, Ptr<cpufreq_policy> policy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_cpu_idle_miss(Ptr<?> __data, @Unsigned int cpu_id,
      @Unsigned int state, boolean below) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_cpu_latency_qos_request(Ptr<?> __data, int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_cpuhp_enter($arg1, $arg2, $arg3, $arg4, (int (*)(unsigned int))$arg5)")
  public static void perf_trace_cpuhp_enter(Ptr<?> __data, @Unsigned int cpu, int target, int idx,
      Ptr<?> fun) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_cpuhp_exit(Ptr<?> __data, @Unsigned int cpu, int state, int idx,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_cpuhp_multi_enter($arg1, $arg2, $arg3, $arg4, (int (*)(unsigned int, struct hlist_node*))$arg5, $arg6)")
  public static void perf_trace_cpuhp_multi_enter(Ptr<?> __data, @Unsigned int cpu, int target,
      int idx, Ptr<?> fun, Ptr<hlist_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_csd_function(Ptr<?> __data,
      @OriginalName("smp_call_func_t") Ptr<?> func,
      Ptr<@OriginalName("call_single_data_t") __call_single_data> csd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_csd_queue_cpu($arg1, (const unsigned int)$arg2, $arg3, $arg4, $arg5)")
  public static void perf_trace_csd_queue_cpu(Ptr<?> __data, @Unsigned int cpu,
      @Unsigned long callsite, @OriginalName("smp_call_func_t") Ptr<?> func,
      Ptr<@OriginalName("call_single_data_t") __call_single_data> csd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ctime(Ptr<?> __data, Ptr<inode> inode, Ptr<timespec64> ctime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ctime_ns_xchg(Ptr<?> __data, Ptr<inode> inode, @Unsigned int old,
      @Unsigned int _new, @Unsigned int cur) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_dax_pmd_fault_class(Ptr<?> __data, Ptr<inode> inode,
      Ptr<vm_fault> vmf, @Unsigned long max_pgoff, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_dax_pmd_load_hole_class(Ptr<?> __data, Ptr<inode> inode,
      Ptr<vm_fault> vmf, Ptr<folio> zero_folio, Ptr<?> radix_entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_dax_pte_fault_class(Ptr<?> __data, Ptr<inode> inode,
      Ptr<vm_fault> vmf, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_dax_writeback_one(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned long pgoff, @Unsigned long pglen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_dax_writeback_range_class(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned long start_index, @Unsigned long end_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_del(Ptr<perf_event> p_event, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_destroy(Ptr<perf_event> p_event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_dev_pm_qos_request($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static void perf_trace_dev_pm_qos_request(Ptr<?> __data, String name,
      dev_pm_qos_req_type type, int new_value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_devfreq_frequency(Ptr<?> __data, Ptr<devfreq> devfreq,
      @Unsigned long freq, @Unsigned long prev_freq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_devfreq_monitor(Ptr<?> __data, Ptr<devfreq> devfreq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_device_pm_callback_end(Ptr<?> __data, Ptr<device> dev, int error) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_device_pm_callback_start($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static void perf_trace_device_pm_callback_start(Ptr<?> __data, Ptr<device> dev,
      String pm_ops, int event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_devlink_health_recover_aborted($arg1, (const struct devlink*)$arg2, (const u8*)$arg3, $arg4, $arg5)")
  public static void perf_trace_devlink_health_recover_aborted(Ptr<?> __data, Ptr<devlink> devlink,
      String reporter_name, boolean health_state, @Unsigned long time_since_last_recover) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_devlink_health_report($arg1, (const struct devlink*)$arg2, (const u8*)$arg3, (const u8*)$arg4)")
  public static void perf_trace_devlink_health_report(Ptr<?> __data, Ptr<devlink> devlink,
      String reporter_name, String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_devlink_health_reporter_state_update($arg1, (const struct devlink*)$arg2, (const u8*)$arg3, $arg4)")
  public static void perf_trace_devlink_health_reporter_state_update(Ptr<?> __data,
      Ptr<devlink> devlink, String reporter_name, boolean new_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_devlink_hwerr($arg1, (const struct devlink*)$arg2, $arg3, (const u8*)$arg4)")
  public static void perf_trace_devlink_hwerr(Ptr<?> __data, Ptr<devlink> devlink, int err,
      String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_devlink_hwmsg($arg1, (const struct devlink*)$arg2, $arg3, $arg4, (const u8*)$arg5, $arg6)")
  public static void perf_trace_devlink_hwmsg(Ptr<?> __data, Ptr<devlink> devlink, boolean incoming,
      @Unsigned long type, Ptr<java.lang.Character> buf, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_devlink_trap_report($arg1, (const struct devlink*)$arg2, $arg3, (const struct devlink_trap_metadata*)$arg4)")
  public static void perf_trace_devlink_trap_report(Ptr<?> __data, Ptr<devlink> devlink,
      Ptr<sk_buff> skb, Ptr<devlink_trap_metadata> metadata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_devres($arg1, $arg2, (const u8*)$arg3, $arg4, (const u8*)$arg5, $arg6)")
  public static void perf_trace_devres(Ptr<?> __data, Ptr<device> dev, String op, Ptr<?> node,
      String name, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_dma_alloc_class(Ptr<?> __data, Ptr<device> dev, Ptr<?> virt_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir, @Unsigned @OriginalName("gfp_t") int flags, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_dma_alloc_sgt(Ptr<?> __data, Ptr<device> dev, Ptr<sg_table> sgt,
      @Unsigned long size, dma_data_direction dir, @Unsigned @OriginalName("gfp_t") int flags,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_dma_fence(Ptr<?> __data, Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_dma_fence_unsignaled(Ptr<?> __data, Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_dma_free_class(Ptr<?> __data, Ptr<device> dev, Ptr<?> virt_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_dma_free_sgt(Ptr<?> __data, Ptr<device> dev, Ptr<sg_table> sgt,
      @Unsigned long size, dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_dma_map(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("phys_addr_t") long phys_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_dma_map_sg(Ptr<?> __data, Ptr<device> dev, Ptr<scatterlist> sgl,
      int nents, int ents, dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_dma_map_sg_err(Ptr<?> __data, Ptr<device> dev, Ptr<scatterlist> sgl,
      int nents, int err, dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_dma_sync_sg(Ptr<?> __data, Ptr<device> dev, Ptr<scatterlist> sgl,
      int nents, dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_dma_sync_single(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_dma_unmap(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long addr, @Unsigned long size, dma_data_direction dir,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_dma_unmap_sg(Ptr<?> __data, Ptr<device> dev, Ptr<scatterlist> sgl,
      int nents, dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_dql_stall_detected(Ptr<?> __data, @Unsigned short thrs,
      @Unsigned int len, @Unsigned long last_reap, @Unsigned long hist_head, @Unsigned long now,
      Ptr<java.lang. @Unsigned Long> hist) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_drm_vblank_event(Ptr<?> __data, int crtc, @Unsigned int seq,
      @OriginalName("ktime_t") long time, boolean high_prec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_drm_vblank_event_delivered(Ptr<?> __data, Ptr<drm_file> file,
      int crtc, @Unsigned int seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_drm_vblank_event_queued(Ptr<?> __data, Ptr<drm_file> file, int crtc,
      @Unsigned int seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_emulate_vsyscall(Ptr<?> __data, int nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_error_da_monitor_id(Ptr<?> __data, int id, String state,
      String event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_error_report_template(Ptr<?> __data, error_detector error_detector,
      @Unsigned long id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_event_da_monitor_id(Ptr<?> __data, int id, String state,
      String event, String next_state, boolean final_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_trace_event_init(Ptr<trace_event_call> tp_event, Ptr<perf_event> p_event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_trace_event_reg(Ptr<trace_event_call> tp_event, Ptr<perf_event> p_event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_event_unreg(Ptr<perf_event> p_event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_exceptions(Ptr<?> __data, @Unsigned long address, Ptr<pt_regs> regs,
      @Unsigned long error_code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_exit_mmap(Ptr<?> __data, Ptr<mm_struct> mm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4__bitmap_load(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned long group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4__es_extent(Ptr<?> __data, Ptr<inode> inode,
      Ptr<extent_status> es) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4__es_shrink_enter(Ptr<?> __data, Ptr<super_block> sb,
      int nr_to_scan, int cache_cnt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4__fallocate_mode(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long offset, @OriginalName("loff_t") long len, int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4__folio_op(Ptr<?> __data, Ptr<inode> inode, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4__map_blocks_enter(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk, @Unsigned int len, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4__map_blocks_exit(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned int flags, Ptr<ext4_map_blocks> map, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4__mb_new_pa(Ptr<?> __data, Ptr<ext4_allocation_context> ac,
      Ptr<ext4_prealloc_space> pa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4__mballoc(Ptr<?> __data, Ptr<super_block> sb, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_group_t") int group, @OriginalName("ext4_grpblk_t") int start,
      @OriginalName("ext4_grpblk_t") int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4__trim(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group, @OriginalName("ext4_grpblk_t") int start,
      @OriginalName("ext4_grpblk_t") int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4__truncate(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4__write_begin(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long pos, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4__write_end(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long pos, @Unsigned int len, @Unsigned int copied) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_alloc_da_blocks(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_allocate_blocks(Ptr<?> __data, Ptr<ext4_allocation_request> ar,
      @Unsigned long block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_allocate_inode(Ptr<?> __data, Ptr<inode> inode, Ptr<inode> dir,
      int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_begin_ordered_truncate(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long new_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_collapse_range(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long offset, @OriginalName("loff_t") long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_da_release_space(Ptr<?> __data, Ptr<inode> inode,
      int freed_blocks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_da_reserve_space(Ptr<?> __data, Ptr<inode> inode,
      int nr_resv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_da_update_reserve_space(Ptr<?> __data, Ptr<inode> inode,
      int used_blocks, int quota_claim) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_da_write_folios_end(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long start_pos, @OriginalName("loff_t") long next_pos,
      Ptr<writeback_control> wbc, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_da_write_folios_start(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long start_pos, @OriginalName("loff_t") long next_pos,
      Ptr<writeback_control> wbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_da_write_pages_extent(Ptr<?> __data, Ptr<inode> inode,
      Ptr<ext4_map_blocks> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_discard_blocks(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned long blk, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_discard_preallocations(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_drop_inode(Ptr<?> __data, Ptr<inode> inode, int drop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_ext4_error($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static void perf_trace_ext4_error(Ptr<?> __data, Ptr<super_block> sb, String function,
      @Unsigned int line) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_es_find_extent_range_enter(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_es_find_extent_range_exit(Ptr<?> __data, Ptr<inode> inode,
      Ptr<extent_status> es) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_es_insert_delayed_extent(Ptr<?> __data, Ptr<inode> inode,
      Ptr<extent_status> es, boolean lclu_allocated, boolean end_allocated) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_es_lookup_extent_enter(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_es_lookup_extent_exit(Ptr<?> __data, Ptr<inode> inode,
      Ptr<extent_status> es, int found) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_es_remove_extent(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk,
      @Unsigned @OriginalName("ext4_lblk_t") int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_es_shrink(Ptr<?> __data, Ptr<super_block> sb, int nr_shrunk,
      @Unsigned long scan_time, int nr_skipped, int retried) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_es_shrink_scan_exit(Ptr<?> __data, Ptr<super_block> sb,
      int nr_shrunk, int cache_cnt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_evict_inode(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_ext_convert_to_initialized_enter(Ptr<?> __data,
      Ptr<inode> inode, Ptr<ext4_map_blocks> map, Ptr<ext4_extent> ux) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_ext_convert_to_initialized_fastpath(Ptr<?> __data,
      Ptr<inode> inode, Ptr<ext4_map_blocks> map, Ptr<ext4_extent> ux, Ptr<ext4_extent> ix) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_ext_handle_unwritten_extents(Ptr<?> __data, Ptr<inode> inode,
      Ptr<ext4_map_blocks> map, int flags, @Unsigned int allocated,
      @Unsigned @OriginalName("ext4_fsblk_t") long newblock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_ext_load_extent(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk,
      @Unsigned @OriginalName("ext4_fsblk_t") long pblk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_ext_remove_space(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int start,
      @Unsigned @OriginalName("ext4_lblk_t") int end, int depth) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_ext_remove_space_done(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int start,
      @Unsigned @OriginalName("ext4_lblk_t") int end, int depth, Ptr<partial_cluster> pc,
      @Unsigned @OriginalName("__le16") short eh_entries) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_ext_rm_idx(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_fsblk_t") long pblk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_ext_rm_leaf(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int start, Ptr<ext4_extent> ex,
      Ptr<partial_cluster> pc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_ext_show_extent(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk,
      @Unsigned @OriginalName("ext4_fsblk_t") long pblk, @Unsigned short len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_fallocate_exit(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long offset, @Unsigned int max_blocks, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_fc_cleanup(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal, int full,
      @Unsigned @OriginalName("tid_t") int tid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_fc_commit_start(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned @OriginalName("tid_t") int commit_tid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_fc_commit_stop(Ptr<?> __data, Ptr<super_block> sb, int nblks,
      int reason, @Unsigned @OriginalName("tid_t") int commit_tid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_fc_replay(Ptr<?> __data, Ptr<super_block> sb, int tag, int ino,
      int priv1, int priv2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_fc_replay_scan(Ptr<?> __data, Ptr<super_block> sb, int error,
      int off) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_fc_stats(Ptr<?> __data, Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_fc_track_dentry(Ptr<?> __data,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<dentry> dentry, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_fc_track_inode(Ptr<?> __data,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_fc_track_range(Ptr<?> __data,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode, long start,
      long end, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_forget(Ptr<?> __data, Ptr<inode> inode, int is_metadata,
      @Unsigned long block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_free_blocks(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned long block, @Unsigned long count, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_free_inode(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_fsmap_class(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned int keydev, @Unsigned int agno, @Unsigned long bno, @Unsigned long len,
      @Unsigned long owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_get_implied_cluster_alloc_exit(Ptr<?> __data,
      Ptr<super_block> sb, Ptr<ext4_map_blocks> map, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_getfsmap_class(Ptr<?> __data, Ptr<super_block> sb,
      Ptr<ext4_fsmap> fsmap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_insert_range(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long offset, @OriginalName("loff_t") long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_invalidate_folio_op(Ptr<?> __data, Ptr<folio> folio,
      @Unsigned long offset, @Unsigned long length) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_journal_start_inode(Ptr<?> __data, Ptr<inode> inode,
      int blocks, int rsv_blocks, int revoke_creds, int type, @Unsigned long IP) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_journal_start_reserved(Ptr<?> __data, Ptr<super_block> sb,
      int blocks, @Unsigned long IP) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_journal_start_sb(Ptr<?> __data, Ptr<super_block> sb,
      int blocks, int rsv_blocks, int revoke_creds, int type, @Unsigned long IP) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_lazy_itable_init(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_load_inode(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned long ino) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_mark_inode_dirty(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned long IP) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_mb_discard_preallocations(Ptr<?> __data, Ptr<super_block> sb,
      int needed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_mb_release_group_pa(Ptr<?> __data, Ptr<super_block> sb,
      Ptr<ext4_prealloc_space> pa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_mb_release_inode_pa(Ptr<?> __data, Ptr<ext4_prealloc_space> pa,
      @Unsigned long block, @Unsigned int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_mballoc_alloc(Ptr<?> __data, Ptr<ext4_allocation_context> ac) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_mballoc_prealloc(Ptr<?> __data,
      Ptr<ext4_allocation_context> ac) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_nfs_commit_metadata(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_other_inode_update_time(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ino_t") long orig_ino) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_prefetch_bitmaps(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group,
      @Unsigned @OriginalName("ext4_group_t") int next, @Unsigned int prefetch_ios) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_read_block_bitmap_load(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned long group, boolean prefetch) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_remove_blocks(Ptr<?> __data, Ptr<inode> inode,
      Ptr<ext4_extent> ex, @Unsigned @OriginalName("ext4_lblk_t") int from,
      @Unsigned @OriginalName("ext4_fsblk_t") long to, Ptr<partial_cluster> pc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_request_blocks(Ptr<?> __data,
      Ptr<ext4_allocation_request> ar) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_request_inode(Ptr<?> __data, Ptr<inode> dir, int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_shutdown(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_sync_file_enter(Ptr<?> __data, Ptr<file> file, int datasync) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_sync_file_exit(Ptr<?> __data, Ptr<inode> inode, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_sync_fs(Ptr<?> __data, Ptr<super_block> sb, int wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_unlink_enter(Ptr<?> __data, Ptr<inode> parent,
      Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_unlink_exit(Ptr<?> __data, Ptr<dentry> dentry, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_update_sb(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_fsblk_t") long fsblk, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_writepages(Ptr<?> __data, Ptr<inode> inode,
      Ptr<writeback_control> wbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ext4_writepages_result(Ptr<?> __data, Ptr<inode> inode,
      Ptr<writeback_control> wbc, int ret, int pages_written) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_extlog_mem_event($arg1, $arg2, $arg3, (const struct {\n"
          + "  u8 b[16];\n"
          + "}*)$arg4, (const u8*)$arg5, $arg6)")
  public static void perf_trace_extlog_mem_event(Ptr<?> __data, Ptr<cper_sec_mem_err> mem,
      @Unsigned int err_seq, Ptr<@OriginalName("guid_t") uuid_t> fru_id, String fru_text,
      char sev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_fdb_delete(Ptr<?> __data, Ptr<net_bridge> br,
      Ptr<net_bridge_fdb_entry> f) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_fib6_table_lookup($arg1, (const struct net*)$arg2, (const struct fib6_result*)$arg3, $arg4, (const struct flowi6*)$arg5)")
  public static void perf_trace_fib6_table_lookup(Ptr<?> __data, Ptr<net> net, Ptr<fib6_result> res,
      Ptr<fib6_table> table, Ptr<flowi6> flp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_fib_table_lookup($arg1, $arg2, (const struct flowi4*)$arg3, (const struct fib_nh_common*)$arg4, $arg5)")
  public static void perf_trace_fib_table_lookup(Ptr<?> __data, @Unsigned int tb_id,
      Ptr<flowi4> flp, Ptr<fib_nh_common> nhc, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_file_check_and_advance_wb_err(Ptr<?> __data, Ptr<file> file,
      @Unsigned @OriginalName("errseq_t") int old) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_filelock_lease(Ptr<?> __data, Ptr<inode> inode,
      Ptr<file_lease> fl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_filelock_lock(Ptr<?> __data, Ptr<inode> inode, Ptr<file_lock> fl,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_filemap_set_wb_err(Ptr<?> __data, Ptr<address_space> mapping,
      @Unsigned @OriginalName("errseq_t") int eseq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_fill_mg_cmtime(Ptr<?> __data, Ptr<inode> inode,
      Ptr<timespec64> ctime, Ptr<timespec64> mtime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_finish_task_reaping(Ptr<?> __data, int pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_flush_foreign(Ptr<?> __data, Ptr<bdi_writeback> wb,
      @Unsigned int frn_bdi_id, @Unsigned int frn_memcg_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_free_vmap_area_noflush(Ptr<?> __data, @Unsigned long va_start,
      @Unsigned long nr_lazy, @Unsigned long nr_lazy_max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_fuse_request_end($arg1, (const struct fuse_req*)$arg2)")
  public static void perf_trace_fuse_request_end(Ptr<?> __data, Ptr<fuse_req> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_fuse_request_send($arg1, (const struct fuse_req*)$arg2)")
  public static void perf_trace_fuse_request_send(Ptr<?> __data, Ptr<fuse_req> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_generic_add_lease(Ptr<?> __data, Ptr<inode> inode,
      Ptr<file_lease> fl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_global_dirty_state(Ptr<?> __data, @Unsigned long background_thresh,
      @Unsigned long dirty_thresh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_gpio_direction(Ptr<?> __data, @Unsigned int gpio, int in, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_gpio_value(Ptr<?> __data, @Unsigned int gpio, int get, int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_guest_halt_poll_ns(Ptr<?> __data, boolean grow, @Unsigned int _new,
      @Unsigned int old) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_handshake_alert_class($arg1, (const struct sock*)$arg2, $arg3, $arg4)")
  public static void perf_trace_handshake_alert_class(Ptr<?> __data, Ptr<sock> sk, char level,
      char description) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_handshake_complete($arg1, (const struct net*)$arg2, (const struct handshake_req*)$arg3, (const struct sock*)$arg4, $arg5)")
  public static void perf_trace_handshake_complete(Ptr<?> __data, Ptr<net> net,
      Ptr<handshake_req> req, Ptr<sock> sk, int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_handshake_error_class($arg1, (const struct net*)$arg2, (const struct handshake_req*)$arg3, (const struct sock*)$arg4, $arg5)")
  public static void perf_trace_handshake_error_class(Ptr<?> __data, Ptr<net> net,
      Ptr<handshake_req> req, Ptr<sock> sk, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_handshake_event_class($arg1, (const struct net*)$arg2, (const struct handshake_req*)$arg3, (const struct sock*)$arg4)")
  public static void perf_trace_handshake_event_class(Ptr<?> __data, Ptr<net> net,
      Ptr<handshake_req> req, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_handshake_fd_class($arg1, (const struct net*)$arg2, (const struct handshake_req*)$arg3, (const struct sock*)$arg4, $arg5)")
  public static void perf_trace_handshake_fd_class(Ptr<?> __data, Ptr<net> net,
      Ptr<handshake_req> req, Ptr<sock> sk, int fd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_hrtimer_class(Ptr<?> __data, Ptr<hrtimer> hrtimer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_hrtimer_expire_entry(Ptr<?> __data, Ptr<hrtimer> hrtimer,
      Ptr<java.lang. @OriginalName("ktime_t") Long> now) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_hrtimer_setup(Ptr<?> __data, Ptr<hrtimer> hrtimer,
      @OriginalName("clockid_t") int clockid, hrtimer_mode mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_hrtimer_start(Ptr<?> __data, Ptr<hrtimer> hrtimer,
      hrtimer_mode mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_hugetlbfs__inode(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_hugetlbfs_alloc_inode(Ptr<?> __data, Ptr<inode> inode,
      Ptr<inode> dir, int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_hugetlbfs_fallocate(Ptr<?> __data, Ptr<inode> inode, int mode,
      @OriginalName("loff_t") long offset, @OriginalName("loff_t") long len, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_hugetlbfs_setattr(Ptr<?> __data, Ptr<inode> inode,
      Ptr<dentry> dentry, Ptr<iattr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_hwmon_attr_class($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static void perf_trace_hwmon_attr_class(Ptr<?> __data, int index, String attr_name,
      long val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_hwmon_attr_show_string($arg1, $arg2, (const u8*)$arg3, (const u8*)$arg4)")
  public static void perf_trace_hwmon_attr_show_string(Ptr<?> __data, int index, String attr_name,
      String s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_hyperv_mmu_flush_tlb_multi($arg1, (const struct cpumask*)$arg2, (const struct flush_tlb_info*)$arg3)")
  public static void perf_trace_hyperv_mmu_flush_tlb_multi(Ptr<?> __data, Ptr<cpumask> cpus,
      Ptr<flush_tlb_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_hyperv_nested_flush_guest_mapping(Ptr<?> __data, @Unsigned long as,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_hyperv_nested_flush_guest_mapping_range(Ptr<?> __data,
      @Unsigned long as, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_hyperv_send_ipi_mask($arg1, (const struct cpumask*)$arg2, $arg3)")
  public static void perf_trace_hyperv_send_ipi_mask(Ptr<?> __data, Ptr<cpumask> cpus, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_hyperv_send_ipi_one(Ptr<?> __data, int cpu, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_i2c_read($arg1, (const struct i2c_adapter*)$arg2, (const struct i2c_msg*)$arg3, $arg4)")
  public static void perf_trace_i2c_read(Ptr<?> __data, Ptr<i2c_adapter> adap, Ptr<i2c_msg> msg,
      int num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_i2c_reply($arg1, (const struct i2c_adapter*)$arg2, (const struct i2c_msg*)$arg3, $arg4)")
  public static void perf_trace_i2c_reply(Ptr<?> __data, Ptr<i2c_adapter> adap, Ptr<i2c_msg> msg,
      int num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_i2c_result($arg1, (const struct i2c_adapter*)$arg2, $arg3, $arg4)")
  public static void perf_trace_i2c_result(Ptr<?> __data, Ptr<i2c_adapter> adap, int num, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_i2c_slave($arg1, (const struct i2c_client*)$arg2, $arg3, $arg4, $arg5)")
  public static void perf_trace_i2c_slave(Ptr<?> __data, Ptr<i2c_client> client,
      i2c_slave_event event, Ptr<java.lang.Character> val, int cb_ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_i2c_write($arg1, (const struct i2c_adapter*)$arg2, (const struct i2c_msg*)$arg3, $arg4)")
  public static void perf_trace_i2c_write(Ptr<?> __data, Ptr<i2c_adapter> adap, Ptr<i2c_msg> msg,
      int num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_icc_set_bw(Ptr<?> __data, Ptr<icc_path> p, Ptr<icc_node> n, int i,
      @Unsigned int avg_bw, @Unsigned int peak_bw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_icc_set_bw_end(Ptr<?> __data, Ptr<icc_path> p, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_icmp_send($arg1, (const struct sk_buff*)$arg2, $arg3, $arg4)")
  public static void perf_trace_icmp_send(Ptr<?> __data, Ptr<sk_buff> skb, int type, int code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_inet_sk_error_report($arg1, (const struct sock*)$arg2)")
  public static void perf_trace_inet_sk_error_report(Ptr<?> __data, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_inet_sock_set_state($arg1, (const struct sock*)$arg2, (const int)$arg3, (const int)$arg4)")
  public static void perf_trace_inet_sock_set_state(Ptr<?> __data, Ptr<sock> sk, int oldstate,
      int newstate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_trace_init(Ptr<perf_event> p_event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_initcall_finish(Ptr<?> __data,
      @OriginalName("initcall_t") Ptr<?> func, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_initcall_level($arg1, (const u8*)$arg2)")
  public static void perf_trace_initcall_level(Ptr<?> __data, String level) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_initcall_start(Ptr<?> __data,
      @OriginalName("initcall_t") Ptr<?> func) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_inode_foreign_history(Ptr<?> __data, Ptr<inode> inode,
      Ptr<writeback_control> wbc, @Unsigned int history) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_inode_switch_wbs(Ptr<?> __data, Ptr<inode> inode,
      Ptr<bdi_writeback> old_wb, Ptr<bdi_writeback> new_wb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_io_uring_complete(Ptr<?> __data, Ptr<io_ring_ctx> ctx, Ptr<?> req,
      Ptr<io_uring_cqe> cqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_io_uring_cqe_overflow(Ptr<?> __data, Ptr<?> ctx,
      @Unsigned long user_data, int res, @Unsigned int cflags, Ptr<?> ocqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_io_uring_cqring_wait(Ptr<?> __data, Ptr<?> ctx, int min_events) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_io_uring_create(Ptr<?> __data, int fd, Ptr<?> ctx,
      @Unsigned int sq_entries, @Unsigned int cq_entries, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_io_uring_defer(Ptr<?> __data, Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_io_uring_fail_link(Ptr<?> __data, Ptr<io_kiocb> req,
      Ptr<io_kiocb> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_io_uring_file_get(Ptr<?> __data, Ptr<io_kiocb> req, int fd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_io_uring_link(Ptr<?> __data, Ptr<io_kiocb> req,
      Ptr<io_kiocb> target_req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_io_uring_local_work_run(Ptr<?> __data, Ptr<?> ctx, int count,
      @Unsigned int loops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_io_uring_poll_arm(Ptr<?> __data, Ptr<io_kiocb> req, int mask,
      int events) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_io_uring_queue_async_work(Ptr<?> __data, Ptr<io_kiocb> req,
      int rw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_io_uring_register(Ptr<?> __data, Ptr<?> ctx, @Unsigned int opcode,
      @Unsigned int nr_files, @Unsigned int nr_bufs, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_io_uring_req_failed($arg1, (const struct io_uring_sqe*)$arg2, $arg3, $arg4)")
  public static void perf_trace_io_uring_req_failed(Ptr<?> __data, Ptr<io_uring_sqe> sqe,
      Ptr<io_kiocb> req, int error) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_io_uring_short_write(Ptr<?> __data, Ptr<?> ctx, @Unsigned long fpos,
      @Unsigned long wanted, @Unsigned long got) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_io_uring_submit_req(Ptr<?> __data, Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_io_uring_task_add(Ptr<?> __data, Ptr<io_kiocb> req, int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_io_uring_task_work_run(Ptr<?> __data, Ptr<?> tctx,
      @Unsigned int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_iocg_inuse_update($arg1, $arg2, (const u8*)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void perf_trace_iocg_inuse_update(Ptr<?> __data, Ptr<ioc_gq> iocg, String path,
      Ptr<ioc_now> now, @Unsigned int old_inuse, @Unsigned int new_inuse,
      @Unsigned long old_hw_inuse, @Unsigned long new_hw_inuse) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_iocost_ioc_vrate_adj(Ptr<?> __data, Ptr<ioc> ioc,
      @Unsigned long new_vrate, Ptr<java.lang. @Unsigned Integer> missed_ppm,
      @Unsigned int rq_wait_pct, int nr_lagging, int nr_shortages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_iocost_iocg_forgive_debt($arg1, $arg2, (const u8*)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8, $arg9)")
  public static void perf_trace_iocost_iocg_forgive_debt(Ptr<?> __data, Ptr<ioc_gq> iocg,
      String path, Ptr<ioc_now> now, @Unsigned int usage_pct, @Unsigned long old_debt,
      @Unsigned long new_debt, @Unsigned long old_delay, @Unsigned long new_delay) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_iocost_iocg_state($arg1, $arg2, (const u8*)$arg3, $arg4, $arg5, $arg6, $arg7)")
  public static void perf_trace_iocost_iocg_state(Ptr<?> __data, Ptr<ioc_gq> iocg, String path,
      Ptr<ioc_now> now, @Unsigned long last_period, @Unsigned long cur_period,
      @Unsigned long vtime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_iomap_add_to_ioend(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned long pos, @Unsigned int dirty_len, Ptr<iomap> iomap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_iomap_class(Ptr<?> __data, Ptr<inode> inode, Ptr<iomap> iomap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_iomap_dio_complete(Ptr<?> __data, Ptr<kiocb> iocb, int error,
      @OriginalName("ssize_t") long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_iomap_dio_rw_begin(Ptr<?> __data, Ptr<kiocb> iocb,
      Ptr<iov_iter> iter, @Unsigned int dio_flags, @Unsigned long done_before) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_iomap_iter($arg1, $arg2, (const void*)$arg3, $arg4)")
  public static void perf_trace_iomap_iter(Ptr<?> __data, Ptr<iomap_iter> iter, Ptr<?> ops,
      @Unsigned long caller) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_iomap_range_class(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long off, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_iomap_readpage_class(Ptr<?> __data, Ptr<inode> inode,
      int nr_pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_iommu_device_event(Ptr<?> __data, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_iommu_error(Ptr<?> __data, Ptr<device> dev, @Unsigned long iova,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_iommu_group_event(Ptr<?> __data, int group_id, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_ipi_send_cpu($arg1, (const unsigned int)$arg2, $arg3, $arg4)")
  public static void perf_trace_ipi_send_cpu(Ptr<?> __data, @Unsigned int cpu,
      @Unsigned long callsite, Ptr<?> callback) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_ipi_send_cpumask($arg1, (const struct cpumask*)$arg2, $arg3, $arg4)")
  public static void perf_trace_ipi_send_cpumask(Ptr<?> __data, Ptr<cpumask> cpumask,
      @Unsigned long callsite, Ptr<?> callback) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_irq_handler_entry(Ptr<?> __data, int irq, Ptr<irqaction> action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_irq_handler_exit(Ptr<?> __data, int irq, Ptr<irqaction> action,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_irq_matrix_cpu(Ptr<?> __data, int bit, @Unsigned int cpu,
      Ptr<irq_matrix> matrix, Ptr<cpumap> cmap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_irq_matrix_global(Ptr<?> __data, Ptr<irq_matrix> matrix) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_irq_matrix_global_update(Ptr<?> __data, int bit,
      Ptr<irq_matrix> matrix) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_irq_noise($arg1, $arg2, (const u8*)$arg3, $arg4, $arg5)")
  public static void perf_trace_irq_noise(Ptr<?> __data, int vector, String desc,
      @Unsigned long start, @Unsigned long duration) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_itimer_expire(Ptr<?> __data, int which, Ptr<pid> pid,
      @Unsigned long now) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_itimer_state($arg1, $arg2, (const const struct itimerspec64*)$arg3, $arg4)")
  public static void perf_trace_itimer_state(Ptr<?> __data, int which, Ptr<itimerspec64> value,
      @Unsigned long expires) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_jbd2_checkpoint(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_jbd2_checkpoint_stats(Ptr<?> __data,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("tid_t") int tid,
      Ptr<transaction_chp_stats_s> stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_jbd2_commit(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal,
      Ptr<@OriginalName("transaction_t") transaction_s> commit_transaction) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_jbd2_end_commit(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal,
      Ptr<@OriginalName("transaction_t") transaction_s> commit_transaction) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_jbd2_handle_extend(Ptr<?> __data,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("tid_t") int tid,
      @Unsigned int type, @Unsigned int line_no, int buffer_credits, int requested_blocks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_jbd2_handle_start_class(Ptr<?> __data,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("tid_t") int tid,
      @Unsigned int type, @Unsigned int line_no, int requested_blocks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_jbd2_handle_stats(Ptr<?> __data,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("tid_t") int tid,
      @Unsigned int type, @Unsigned int line_no, int interval, int sync, int requested_blocks,
      int dirtied_blocks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_jbd2_journal_shrink(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal, @Unsigned long nr_to_scan,
      @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_jbd2_lock_buffer_stall(Ptr<?> __data,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned long stall_ms) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_jbd2_run_stats(Ptr<?> __data,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("tid_t") int tid,
      Ptr<transaction_run_stats_s> stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_jbd2_shrink_checkpoint_list(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal,
      @Unsigned @OriginalName("tid_t") int first_tid, @Unsigned @OriginalName("tid_t") int tid,
      @Unsigned @OriginalName("tid_t") int last_tid, @Unsigned long nr_freed,
      @Unsigned @OriginalName("tid_t") int next_tid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_jbd2_shrink_scan_exit(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal, @Unsigned long nr_to_scan,
      @Unsigned long nr_shrunk, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_jbd2_submit_inode_data(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_jbd2_update_log_tail(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal,
      @Unsigned @OriginalName("tid_t") int first_tid, @Unsigned long block_nr,
      @Unsigned long freed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_jbd2_write_superblock(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal,
      @Unsigned @OriginalName("blk_opf_t") int write_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_kcompactd_wake_template(Ptr<?> __data, int nid, int order,
      zone_type highest_zoneidx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_kfree($arg1, $arg2, (const void*)$arg3)")
  public static void perf_trace_kfree(Ptr<?> __data, @Unsigned long call_site, Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_kfree_skb(Ptr<?> __data, Ptr<sk_buff> skb, Ptr<?> location,
      skb_drop_reason reason, Ptr<sock> rx_sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_kmalloc($arg1, $arg2, (const void*)$arg3, $arg4, $arg5, $arg6, $arg7)")
  public static void perf_trace_kmalloc(Ptr<?> __data, @Unsigned long call_site, Ptr<?> ptr,
      @Unsigned long bytes_req, @Unsigned long bytes_alloc,
      @Unsigned @OriginalName("gfp_t") int gfp_flags, int node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_kmem_cache_alloc($arg1, $arg2, (const void*)$arg3, $arg4, $arg5, $arg6)")
  public static void perf_trace_kmem_cache_alloc(Ptr<?> __data, @Unsigned long call_site,
      Ptr<?> ptr, Ptr<kmem_cache> s, @Unsigned @OriginalName("gfp_t") int gfp_flags, int node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_kmem_cache_free($arg1, $arg2, (const void*)$arg3, (const struct kmem_cache*)$arg4)")
  public static void perf_trace_kmem_cache_free(Ptr<?> __data, @Unsigned long call_site, Ptr<?> ptr,
      Ptr<kmem_cache> s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ksm_advisor(Ptr<?> __data, long scan_time,
      @Unsigned long pages_to_scan, @Unsigned int cpu_percent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ksm_enter_exit_template(Ptr<?> __data, Ptr<?> mm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ksm_merge_one_page(Ptr<?> __data, @Unsigned long pfn,
      Ptr<?> rmap_item, Ptr<?> mm, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ksm_merge_with_ksm_page(Ptr<?> __data, Ptr<?> ksm_page,
      @Unsigned long pfn, Ptr<?> rmap_item, Ptr<?> mm, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ksm_remove_ksm_page(Ptr<?> __data, @Unsigned long pfn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ksm_remove_rmap_item(Ptr<?> __data, @Unsigned long pfn,
      Ptr<?> rmap_item, Ptr<?> mm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_ksm_scan_template(Ptr<?> __data, int seq,
      @Unsigned int rmap_entries) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_leases_conflict(Ptr<?> __data, boolean conflict,
      Ptr<file_lease> lease, Ptr<file_lease> breaker) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_locks_get_lock_context(Ptr<?> __data, Ptr<inode> inode, int type,
      Ptr<file_lock_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_ma_op($arg1, (const u8*)$arg2, $arg3)")
  public static void perf_trace_ma_op(Ptr<?> __data, String fn, Ptr<ma_state> mas) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_ma_read($arg1, (const u8*)$arg2, $arg3)")
  public static void perf_trace_ma_read(Ptr<?> __data, String fn, Ptr<ma_state> mas) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_ma_write($arg1, (const u8*)$arg2, $arg3, $arg4, $arg5)")
  public static void perf_trace_ma_write(Ptr<?> __data, String fn, Ptr<ma_state> mas,
      @Unsigned long piv, Ptr<?> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_map(Ptr<?> __data, @Unsigned long iova,
      @Unsigned @OriginalName("phys_addr_t") long paddr, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mark_victim(Ptr<?> __data, Ptr<task_struct> task,
      @Unsigned @OriginalName("uid_t") int uid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_mc_event($arg1, (const unsigned int)$arg2, (const u8*)$arg3, (const u8*)$arg4, (const int)$arg5, (const u8)$arg6, (const s8)$arg7, (const s8)$arg8, (const s8)$arg9, $arg10, (const u8)$arg11, $arg12, (const u8*)$arg13)")
  public static void perf_trace_mc_event(Ptr<?> __data, @Unsigned int err_type, String error_msg,
      String label, int error_count, char mc_index, @OriginalName("s8") byte top_layer,
      @OriginalName("s8") byte mid_layer, @OriginalName("s8") byte low_layer,
      @Unsigned long address, char grain_bits, @Unsigned long syndrome, String driver_detail) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mce_record(Ptr<?> __data, Ptr<mce_hw_err> err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_mctp_key_acquire($arg1, (const struct mctp_sk_key*)$arg2)")
  public static void perf_trace_mctp_key_acquire(Ptr<?> __data, Ptr<mctp_sk_key> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_mctp_key_release($arg1, (const struct mctp_sk_key*)$arg2, $arg3)")
  public static void perf_trace_mctp_key_release(Ptr<?> __data, Ptr<mctp_sk_key> key, int reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mdio_access(Ptr<?> __data, Ptr<mii_bus> bus, char read, char addr,
      @Unsigned int regnum, @Unsigned short val, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_mem_connect($arg1, (const struct xdp_mem_allocator*)$arg2, (const struct xdp_rxq_info*)$arg3)")
  public static void perf_trace_mem_connect(Ptr<?> __data, Ptr<xdp_mem_allocator> xa,
      Ptr<xdp_rxq_info> rxq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_mem_disconnect($arg1, (const struct xdp_mem_allocator*)$arg2)")
  public static void perf_trace_mem_disconnect(Ptr<?> __data, Ptr<xdp_mem_allocator> xa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_memcg_flush_stats(Ptr<?> __data, Ptr<mem_cgroup> memcg,
      long stats_updates, boolean force, boolean needs_flush) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_memcg_rstat_events(Ptr<?> __data, Ptr<mem_cgroup> memcg, int item,
      @Unsigned long val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_memcg_rstat_stats(Ptr<?> __data, Ptr<mem_cgroup> memcg, int item,
      int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_memory_failure_event(Ptr<?> __data, @Unsigned long pfn, int type,
      int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_migration_pmd(Ptr<?> __data, @Unsigned long addr,
      @Unsigned long pmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_migration_pte(Ptr<?> __data, @Unsigned long addr,
      @Unsigned long pte, int order) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_calculate_totalreserve_pages(Ptr<?> __data,
      @Unsigned long totalreserve_pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_collapse_huge_page(Ptr<?> __data, Ptr<mm_struct> mm,
      int isolated, int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_collapse_huge_page_isolate(Ptr<?> __data, Ptr<folio> folio,
      int none_or_zero, int referenced, boolean writable, int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_collapse_huge_page_swapin(Ptr<?> __data, Ptr<mm_struct> mm,
      int swapped_in, int referenced, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_compaction_begin(Ptr<?> __data, Ptr<compact_control> cc,
      @Unsigned long zone_start, @Unsigned long zone_end, boolean sync) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_compaction_defer_template(Ptr<?> __data, Ptr<zone> zone,
      int order) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_compaction_end(Ptr<?> __data, Ptr<compact_control> cc,
      @Unsigned long zone_start, @Unsigned long zone_end, boolean sync, int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_compaction_isolate_template(Ptr<?> __data,
      @Unsigned long start_pfn, @Unsigned long end_pfn, @Unsigned long nr_scanned,
      @Unsigned long nr_taken) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_compaction_kcompactd_sleep(Ptr<?> __data, int nid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_compaction_migratepages(Ptr<?> __data,
      @Unsigned int nr_migratepages, @Unsigned int nr_succeeded) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_compaction_suitable_template(Ptr<?> __data, Ptr<zone> zone,
      int order, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_compaction_try_to_compact_pages(Ptr<?> __data, int order,
      @Unsigned @OriginalName("gfp_t") int gfp_mask, int prio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_filemap_fault(Ptr<?> __data, Ptr<address_space> mapping,
      @Unsigned long index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_filemap_op_page_cache(Ptr<?> __data, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_filemap_op_page_cache_range(Ptr<?> __data,
      Ptr<address_space> mapping, @Unsigned long index, @Unsigned long last_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_khugepaged_collapse_file(Ptr<?> __data, Ptr<mm_struct> mm,
      Ptr<folio> new_folio, @Unsigned long index, @Unsigned long addr, boolean is_shmem,
      Ptr<file> file, int nr, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_khugepaged_scan_file(Ptr<?> __data, Ptr<mm_struct> mm,
      Ptr<folio> folio, Ptr<file> file, int present, int swap, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_khugepaged_scan_pmd(Ptr<?> __data, Ptr<mm_struct> mm,
      Ptr<folio> folio, boolean writable, int referenced, int none_or_zero, int status,
      int unmapped) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_lru_activate(Ptr<?> __data, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_lru_insertion(Ptr<?> __data, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_migrate_pages(Ptr<?> __data, @Unsigned long succeeded,
      @Unsigned long failed, @Unsigned long thp_succeeded, @Unsigned long thp_failed,
      @Unsigned long thp_split, @Unsigned long large_folio_split, migrate_mode mode, int reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_migrate_pages_start(Ptr<?> __data, migrate_mode mode,
      int reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_page(Ptr<?> __data, Ptr<page> page, @Unsigned int order,
      int migratetype, int percpu_refill) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_page_alloc(Ptr<?> __data, Ptr<page> page, @Unsigned int order,
      @Unsigned @OriginalName("gfp_t") int gfp_flags, int migratetype) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_page_alloc_extfrag(Ptr<?> __data, Ptr<page> page,
      int alloc_order, int fallback_order, int alloc_migratetype, int fallback_migratetype) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_page_free(Ptr<?> __data, Ptr<page> page, @Unsigned int order) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_page_free_batched(Ptr<?> __data, Ptr<page> page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_page_pcpu_drain(Ptr<?> __data, Ptr<page> page,
      @Unsigned int order, int migratetype) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_setup_per_zone_lowmem_reserve(Ptr<?> __data, Ptr<zone> zone,
      Ptr<zone> upper_zone, long lowmem_reserve) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_setup_per_zone_wmarks(Ptr<?> __data, Ptr<zone> zone) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_shrink_slab_end(Ptr<?> __data, Ptr<shrinker> shr, int nid,
      int shrinker_retval, long unused_scan_cnt, long new_scan_cnt, long total_scan) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_shrink_slab_start(Ptr<?> __data, Ptr<shrinker> shr,
      Ptr<shrink_control> sc, long nr_objects_to_shrink, @Unsigned long cache_items,
      @Unsigned long delta, @Unsigned long total_scan, int priority) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_vmscan_direct_reclaim_begin_template(Ptr<?> __data, int order,
      @Unsigned @OriginalName("gfp_t") int gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_vmscan_direct_reclaim_end_template(Ptr<?> __data,
      @Unsigned long nr_reclaimed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_vmscan_kswapd_sleep(Ptr<?> __data, int nid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_vmscan_kswapd_wake(Ptr<?> __data, int nid, int zid, int order) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_vmscan_lru_isolate(Ptr<?> __data, int highest_zoneidx, int order,
      @Unsigned long nr_requested, @Unsigned long nr_scanned, @Unsigned long nr_skipped,
      @Unsigned long nr_taken, int lru) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_vmscan_lru_shrink_active(Ptr<?> __data, int nid,
      @Unsigned long nr_taken, @Unsigned long nr_active, @Unsigned long nr_deactivated,
      @Unsigned long nr_referenced, int priority, int file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_vmscan_lru_shrink_inactive(Ptr<?> __data, int nid,
      @Unsigned long nr_scanned, @Unsigned long nr_reclaimed, Ptr<reclaim_stat> stat, int priority,
      int file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_vmscan_node_reclaim_begin(Ptr<?> __data, int nid, int order,
      @Unsigned @OriginalName("gfp_t") int gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_vmscan_reclaim_pages(Ptr<?> __data, int nid,
      @Unsigned long nr_scanned, @Unsigned long nr_reclaimed, Ptr<reclaim_stat> stat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_vmscan_throttled(Ptr<?> __data, int nid, int usec_timeout,
      int usec_delayed, int reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_vmscan_wakeup_kswapd(Ptr<?> __data, int nid, int zid, int order,
      @Unsigned @OriginalName("gfp_t") int gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mm_vmscan_write_folio(Ptr<?> __data, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mmap_lock(Ptr<?> __data, Ptr<mm_struct> mm, boolean write) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mmap_lock_acquire_returned(Ptr<?> __data, Ptr<mm_struct> mm,
      boolean write, boolean success) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mmc_request_done(Ptr<?> __data, Ptr<mmc_host> host,
      Ptr<mmc_request> mrq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mmc_request_start(Ptr<?> __data, Ptr<mmc_host> host,
      Ptr<mmc_request> mrq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_module_free(Ptr<?> __data, Ptr<module> mod) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_module_load(Ptr<?> __data, Ptr<module> mod) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_module_refcnt(Ptr<?> __data, Ptr<module> mod, @Unsigned long ip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_module_request(Ptr<?> __data, String name, boolean wait,
      @Unsigned long ip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mon_llc_occupancy_limbo(Ptr<?> __data, @Unsigned int ctrl_hw_id,
      @Unsigned int mon_hw_id, int domain_id, @Unsigned long llc_occupancy_bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mptcp_dump_mpext(Ptr<?> __data, Ptr<mptcp_ext> mpext) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_mptcp_subflow_get_send(Ptr<?> __data,
      Ptr<mptcp_subflow_context> subflow) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_msr_trace_class(Ptr<?> __data, @Unsigned int msr,
      @Unsigned long val, int failed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_napi_poll(Ptr<?> __data, Ptr<napi_struct> napi, int work,
      int budget) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_neigh__update(Ptr<?> __data, Ptr<neighbour> n, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_neigh_create($arg1, $arg2, $arg3, (const void*)$arg4, (const struct neighbour*)$arg5, $arg6)")
  public static void perf_trace_neigh_create(Ptr<?> __data, Ptr<neigh_table> tbl,
      Ptr<net_device> dev, Ptr<?> pkey, Ptr<neighbour> n, boolean exempt_from_gc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_neigh_update($arg1, $arg2, (const u8*)$arg3, $arg4, $arg5, $arg6)")
  public static void perf_trace_neigh_update(Ptr<?> __data, Ptr<neighbour> n,
      Ptr<java.lang.Character> lladdr, char _new, @Unsigned int flags, @Unsigned int nlmsg_pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_net_dev_rx_exit_template(Ptr<?> __data, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_net_dev_rx_verbose_template($arg1, (const struct sk_buff*)$arg2)")
  public static void perf_trace_net_dev_rx_verbose_template(Ptr<?> __data, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_net_dev_start_xmit($arg1, (const struct sk_buff*)$arg2, (const struct net_device*)$arg3)")
  public static void perf_trace_net_dev_start_xmit(Ptr<?> __data, Ptr<sk_buff> skb,
      Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_net_dev_template(Ptr<?> __data, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_net_dev_xmit(Ptr<?> __data, Ptr<sk_buff> skb, int rc,
      Ptr<net_device> dev, @Unsigned int skb_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_net_dev_xmit_timeout(Ptr<?> __data, Ptr<net_device> dev,
      int queue_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_netlink_extack($arg1, (const u8*)$arg2)")
  public static void perf_trace_netlink_extack(Ptr<?> __data, String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_nmi_handler(Ptr<?> __data, Ptr<?> handler, long delta_ns,
      int handled) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_nmi_noise(Ptr<?> __data, @Unsigned long start,
      @Unsigned long duration) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_non_standard_event($arg1, (const struct {\n"
          + "  u8 b[16];\n"
          + "}*)$arg2, (const struct {\n"
          + "  u8 b[16];\n"
          + "}*)$arg3, (const u8*)$arg4, (const u8)$arg5, (const u8*)$arg6, (const unsigned int)$arg7)")
  public static void perf_trace_non_standard_event(Ptr<?> __data,
      Ptr<@OriginalName("guid_t") uuid_t> sec_type, Ptr<@OriginalName("guid_t") uuid_t> fru_id,
      String fru_text, char sev, Ptr<java.lang.Character> err, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_notifier_info(Ptr<?> __data, Ptr<?> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_oom_score_adj_update(Ptr<?> __data, Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_osnoise_sample(Ptr<?> __data, Ptr<osnoise_sample> s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_page_pool_release($arg1, (const struct page_pool*)$arg2, $arg3, $arg4, $arg5)")
  public static void perf_trace_page_pool_release(Ptr<?> __data, Ptr<page_pool> pool, int inflight,
      @Unsigned int hold, @Unsigned int release) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_page_pool_state_hold($arg1, (const struct page_pool*)$arg2, $arg3, $arg4)")
  public static void perf_trace_page_pool_state_hold(Ptr<?> __data, Ptr<page_pool> pool,
      @Unsigned @OriginalName("netmem_ref") long netmem, @Unsigned int hold) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_page_pool_state_release($arg1, (const struct page_pool*)$arg2, $arg3, $arg4)")
  public static void perf_trace_page_pool_state_release(Ptr<?> __data, Ptr<page_pool> pool,
      @Unsigned @OriginalName("netmem_ref") long netmem, @Unsigned int release) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_page_pool_update_nid($arg1, (const struct page_pool*)$arg2, $arg3)")
  public static void perf_trace_page_pool_update_nid(Ptr<?> __data, Ptr<page_pool> pool,
      int new_nid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_percpu_alloc_percpu(Ptr<?> __data, @Unsigned long call_site,
      boolean reserved, boolean is_atomic, @Unsigned long size, @Unsigned long align,
      Ptr<?> base_addr, int off, Ptr<?> ptr, @Unsigned long bytes_alloc,
      @Unsigned @OriginalName("gfp_t") int gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_percpu_alloc_percpu_fail(Ptr<?> __data, boolean reserved,
      boolean is_atomic, @Unsigned long size, @Unsigned long align) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_percpu_create_chunk(Ptr<?> __data, Ptr<?> base_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_percpu_destroy_chunk(Ptr<?> __data, Ptr<?> base_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_percpu_free_percpu(Ptr<?> __data, Ptr<?> base_addr, int off,
      Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_pm_qos_update(Ptr<?> __data, pm_qos_req_action action,
      int prev_value, int curr_value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_prq_report(Ptr<?> __data, Ptr<intel_iommu> iommu, Ptr<device> dev,
      @Unsigned long dw0, @Unsigned long dw1, @Unsigned long dw2, @Unsigned long dw3,
      @Unsigned long seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_pseudo_lock_l2(Ptr<?> __data, @Unsigned long l2_hits,
      @Unsigned long l2_miss) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_pseudo_lock_l3(Ptr<?> __data, @Unsigned long l3_hits,
      @Unsigned long l3_miss) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_pseudo_lock_mem_latency(Ptr<?> __data, @Unsigned int latency) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_pstate_sample(Ptr<?> __data, @Unsigned int core_busy,
      @Unsigned int scaled_busy, @Unsigned int from, @Unsigned int to, @Unsigned long mperf,
      @Unsigned long aperf, @Unsigned long tsc, @Unsigned int freq, @Unsigned int io_boost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_purge_vmap_area_lazy(Ptr<?> __data, @Unsigned long start,
      @Unsigned long end, @Unsigned int npurged) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_pwm($arg1, $arg2, (const struct pwm_state*)$arg3, $arg4)")
  public static void perf_trace_pwm(Ptr<?> __data, Ptr<pwm_device> pwm, Ptr<pwm_state> state,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_pwm_read_waveform(Ptr<?> __data, Ptr<pwm_device> pwm, Ptr<?> wfhw,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_pwm_round_waveform_fromhw($arg1, $arg2, (const void*)$arg3, $arg4, $arg5)")
  public static void perf_trace_pwm_round_waveform_fromhw(Ptr<?> __data, Ptr<pwm_device> pwm,
      Ptr<?> wfhw, Ptr<pwm_waveform> wf, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_pwm_round_waveform_tohw($arg1, $arg2, (const struct pwm_waveform*)$arg3, $arg4, $arg5)")
  public static void perf_trace_pwm_round_waveform_tohw(Ptr<?> __data, Ptr<pwm_device> pwm,
      Ptr<pwm_waveform> wf, Ptr<?> wfhw, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_pwm_write_waveform($arg1, $arg2, (const void*)$arg3, $arg4)")
  public static void perf_trace_pwm_write_waveform(Ptr<?> __data, Ptr<pwm_device> pwm, Ptr<?> wfhw,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_qdisc_create($arg1, (const struct Qdisc_ops*)$arg2, $arg3, $arg4)")
  public static void perf_trace_qdisc_create(Ptr<?> __data, Ptr<Qdisc_ops> ops, Ptr<net_device> dev,
      @Unsigned int parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_qdisc_dequeue($arg1, $arg2, (const struct netdev_queue*)$arg3, $arg4, $arg5)")
  public static void perf_trace_qdisc_dequeue(Ptr<?> __data, Ptr<Qdisc> qdisc,
      Ptr<netdev_queue> txq, int packets, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_qdisc_destroy(Ptr<?> __data, Ptr<Qdisc> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_qdisc_enqueue($arg1, $arg2, (const struct netdev_queue*)$arg3, $arg4)")
  public static void perf_trace_qdisc_enqueue(Ptr<?> __data, Ptr<Qdisc> qdisc,
      Ptr<netdev_queue> txq, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_qdisc_reset(Ptr<?> __data, Ptr<Qdisc> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_qi_submit(Ptr<?> __data, Ptr<intel_iommu> iommu, @Unsigned long qw0,
      @Unsigned long qw1, @Unsigned long qw2, @Unsigned long qw3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_rcu_stall_warning($arg1, (const u8*)$arg2, (const u8*)$arg3)")
  public static void perf_trace_rcu_stall_warning(Ptr<?> __data, String rcuname, String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_rcu_utilization($arg1, (const u8*)$arg2)")
  public static void perf_trace_rcu_utilization(Ptr<?> __data, String s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_reclaim_retry_zone(Ptr<?> __data, Ptr<zoneref> zoneref, int order,
      @Unsigned long reclaimable, @Unsigned long available, @Unsigned long min_wmark,
      int no_progress_loops, boolean wmark_check) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_regcache_drop_region(Ptr<?> __data, Ptr<regmap> map,
      @Unsigned int from, @Unsigned int to) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_regcache_sync($arg1, $arg2, (const u8*)$arg3, (const u8*)$arg4)")
  public static void perf_trace_regcache_sync(Ptr<?> __data, Ptr<regmap> map, String type,
      String status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_regmap_async(Ptr<?> __data, Ptr<regmap> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_regmap_block(Ptr<?> __data, Ptr<regmap> map, @Unsigned int reg,
      int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_regmap_bool(Ptr<?> __data, Ptr<regmap> map, boolean flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_regmap_bulk($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static void perf_trace_regmap_bulk(Ptr<?> __data, Ptr<regmap> map, @Unsigned int reg,
      Ptr<?> val, int val_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_regmap_reg(Ptr<?> __data, Ptr<regmap> map, @Unsigned int reg,
      @Unsigned int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_regulator_basic($arg1, (const u8*)$arg2)")
  public static void perf_trace_regulator_basic(Ptr<?> __data, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_regulator_range($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static void perf_trace_regulator_range(Ptr<?> __data, String name, int min, int max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_regulator_value($arg1, (const u8*)$arg2, $arg3)")
  public static void perf_trace_regulator_value(Ptr<?> __data, String name, @Unsigned int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_rpm_internal(Ptr<?> __data, Ptr<device> dev, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_rpm_return_int(Ptr<?> __data, Ptr<device> dev, @Unsigned long ip,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_rpm_status(Ptr<?> __data, Ptr<device> dev, rpm_status status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_rseq_ip_fixup(Ptr<?> __data, @Unsigned long regs_ip,
      @Unsigned long start_ip, @Unsigned long post_commit_offset, @Unsigned long abort_ip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_rseq_update(Ptr<?> __data, Ptr<task_struct> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_rss_stat(Ptr<?> __data, Ptr<mm_struct> mm, int member) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_rtc_alarm_irq_enable(Ptr<?> __data, @Unsigned int enabled,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_rtc_irq_set_freq(Ptr<?> __data, int freq, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_rtc_irq_set_state(Ptr<?> __data, int enabled, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_rtc_offset_class(Ptr<?> __data, long offset, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_rtc_time_alarm_class(Ptr<?> __data,
      @OriginalName("time64_t") long secs, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_rtc_timer_class(Ptr<?> __data, Ptr<rtc_timer> timer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_run_bpf_submit(Ptr<?> raw_data, int size, int rctx,
      Ptr<trace_event_call> call, @Unsigned long count, Ptr<pt_regs> regs, Ptr<hlist_head> head,
      Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_rv_retries_error(Ptr<?> __data, String name, String event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sample_threshold(Ptr<?> __data, @Unsigned long start,
      @Unsigned long duration, @Unsigned long interference) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_sched_ext_dump($arg1, (const u8*)$arg2)")
  public static void perf_trace_sched_ext_dump(Ptr<?> __data, String line) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_sched_ext_event($arg1, (const u8*)$arg2, $arg3)")
  public static void perf_trace_sched_ext_event(Ptr<?> __data, String name, long delta) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_kthread_stop(Ptr<?> __data, Ptr<task_struct> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_kthread_stop_ret(Ptr<?> __data, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_kthread_work_execute_end(Ptr<?> __data,
      Ptr<kthread_work> work, @OriginalName("kthread_work_func_t") Ptr<?> function) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_kthread_work_execute_start(Ptr<?> __data,
      Ptr<kthread_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_kthread_work_queue_work(Ptr<?> __data,
      Ptr<kthread_worker> worker, Ptr<kthread_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_migrate_task(Ptr<?> __data, Ptr<task_struct> p,
      int dest_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_move_numa(Ptr<?> __data, Ptr<task_struct> tsk, int src_cpu,
      int dst_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_numa_pair_template(Ptr<?> __data, Ptr<task_struct> src_tsk,
      int src_cpu, Ptr<task_struct> dst_tsk, int dst_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_pi_setprio(Ptr<?> __data, Ptr<task_struct> tsk,
      Ptr<task_struct> pi_task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_prepare_exec(Ptr<?> __data, Ptr<task_struct> task,
      Ptr<linux_binprm> bprm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_process_exec(Ptr<?> __data, Ptr<task_struct> p,
      @OriginalName("pid_t") int old_pid, Ptr<linux_binprm> bprm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_process_exit(Ptr<?> __data, Ptr<task_struct> p,
      boolean group_dead) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_process_fork(Ptr<?> __data, Ptr<task_struct> parent,
      Ptr<task_struct> child) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_process_hang(Ptr<?> __data, Ptr<task_struct> tsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_process_template(Ptr<?> __data, Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_process_wait(Ptr<?> __data, Ptr<pid> pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_skip_cpuset_numa(Ptr<?> __data, Ptr<task_struct> tsk,
      Ptr<nodemask_t> mem_allowed_ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_skip_vma_numa(Ptr<?> __data, Ptr<mm_struct> mm,
      Ptr<vm_area_struct> vma, numa_vmaskip_reason reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_stat_runtime(Ptr<?> __data, Ptr<task_struct> tsk,
      @Unsigned long runtime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_stat_template(Ptr<?> __data, Ptr<task_struct> tsk,
      @Unsigned long delay) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_switch(Ptr<?> __data, boolean preempt, Ptr<task_struct> prev,
      Ptr<task_struct> next, @Unsigned int prev_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_wake_idle_without_ipi(Ptr<?> __data, int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sched_wakeup_template(Ptr<?> __data, Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_scsi_cmd_done_timeout_template(Ptr<?> __data, Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_scsi_dispatch_cmd_error(Ptr<?> __data, Ptr<scsi_cmnd> cmd,
      int rtn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_scsi_dispatch_cmd_start(Ptr<?> __data, Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_scsi_eh_wakeup(Ptr<?> __data, Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_scsi_prepare_zone_append(Ptr<?> __data, Ptr<scsi_cmnd> cmnd,
      @Unsigned @OriginalName("sector_t") long lba, @Unsigned int wp_offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_scsi_zone_wp_update(Ptr<?> __data, Ptr<scsi_cmnd> cmnd,
      @Unsigned @OriginalName("sector_t") long rq_sector, @Unsigned int wp_offset,
      @Unsigned int good_bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_selinux_audited($arg1, $arg2, $arg3, $arg4, (const u8*)$arg5)")
  public static void perf_trace_selinux_audited(Ptr<?> __data, Ptr<selinux_audit_data> sad,
      String scontext, String tcontext, String tclass) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_signal_deliver(Ptr<?> __data, int sig, Ptr<kernel_siginfo> info,
      Ptr<k_sigaction> ka) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_signal_generate(Ptr<?> __data, int sig, Ptr<kernel_siginfo> info,
      Ptr<task_struct> task, int group, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_sk_data_ready($arg1, (const struct sock*)$arg2)")
  public static void perf_trace_sk_data_ready(Ptr<?> __data, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_skb_copy_datagram_iovec($arg1, (const struct sk_buff*)$arg2, $arg3)")
  public static void perf_trace_skb_copy_datagram_iovec(Ptr<?> __data, Ptr<sk_buff> skb, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_skip_task_reaping(Ptr<?> __data, int pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_smbus_read($arg1, (const struct i2c_adapter*)$arg2, $arg3, $arg4, $arg5, $arg6, $arg7)")
  public static void perf_trace_smbus_read(Ptr<?> __data, Ptr<i2c_adapter> adap,
      @Unsigned short addr, @Unsigned short flags, char read_write, char command, int protocol) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_smbus_reply($arg1, (const struct i2c_adapter*)$arg2, $arg3, $arg4, $arg5, $arg6, $arg7, (const union i2c_smbus_data*)$arg8, $arg9)")
  public static void perf_trace_smbus_reply(Ptr<?> __data, Ptr<i2c_adapter> adap,
      @Unsigned short addr, @Unsigned short flags, char read_write, char command, int protocol,
      Ptr<i2c_smbus_data> data, int res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_smbus_result($arg1, (const struct i2c_adapter*)$arg2, $arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void perf_trace_smbus_result(Ptr<?> __data, Ptr<i2c_adapter> adap,
      @Unsigned short addr, @Unsigned short flags, char read_write, char command, int protocol,
      int res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_smbus_write($arg1, (const struct i2c_adapter*)$arg2, $arg3, $arg4, $arg5, $arg6, $arg7, (const union i2c_smbus_data*)$arg8)")
  public static void perf_trace_smbus_write(Ptr<?> __data, Ptr<i2c_adapter> adap,
      @Unsigned short addr, @Unsigned short flags, char read_write, char command, int protocol,
      Ptr<i2c_smbus_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sock_exceed_buf_limit(Ptr<?> __data, Ptr<sock> sk, Ptr<proto> prot,
      long allocated, int kind) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sock_msg_length(Ptr<?> __data, Ptr<sock> sk, int ret, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sock_rcvqueue_full(Ptr<?> __data, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_softirq(Ptr<?> __data, @Unsigned int vec_nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_softirq_noise(Ptr<?> __data, int vector, @Unsigned long start,
      @Unsigned long duration) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_spi_controller(Ptr<?> __data, Ptr<spi_controller> controller) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_spi_message(Ptr<?> __data, Ptr<spi_message> msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_spi_message_done(Ptr<?> __data, Ptr<spi_message> msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_spi_set_cs(Ptr<?> __data, Ptr<spi_device> spi, boolean enable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_spi_setup(Ptr<?> __data, Ptr<spi_device> spi, int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_spi_transfer(Ptr<?> __data, Ptr<spi_message> msg,
      Ptr<spi_transfer> xfer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_start_task_reaping(Ptr<?> __data, int pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_subflow_check_data_avail(Ptr<?> __data, char status,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_suspend_resume($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static void perf_trace_suspend_resume(Ptr<?> __data, String action, int val,
      boolean start) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_swiotlb_bounced(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long dev_addr, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sync_timeline(Ptr<?> __data, Ptr<sync_timeline> timeline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sys_enter(Ptr<?> __data, Ptr<pt_regs> regs, long id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_sys_exit(Ptr<?> __data, Ptr<pt_regs> regs, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_task_newtask(Ptr<?> __data, Ptr<task_struct> task,
      @Unsigned long clone_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_task_prctl_unknown(Ptr<?> __data, int option, @Unsigned long arg2,
      @Unsigned long arg3, @Unsigned long arg4, @Unsigned long arg5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_task_rename($arg1, $arg2, (const u8*)$arg3)")
  public static void perf_trace_task_rename(Ptr<?> __data, Ptr<task_struct> task, String comm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_tasklet(Ptr<?> __data, Ptr<tasklet_struct> t, Ptr<?> func) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_tcp_ao_event($arg1, (const struct sock*)$arg2, (const struct sk_buff*)$arg3, (const u8)$arg4, (const u8)$arg5, (const u8)$arg6)")
  public static void perf_trace_tcp_ao_event(Ptr<?> __data, Ptr<sock> sk, Ptr<sk_buff> skb,
      char keyid, char rnext, char maclen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_tcp_ao_event_sk($arg1, (const struct sock*)$arg2, (const u8)$arg3, (const u8)$arg4)")
  public static void perf_trace_tcp_ao_event_sk(Ptr<?> __data, Ptr<sock> sk, char keyid,
      char rnext) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_tcp_ao_event_sne($arg1, (const struct sock*)$arg2, $arg3)")
  public static void perf_trace_tcp_ao_event_sne(Ptr<?> __data, Ptr<sock> sk,
      @Unsigned int new_sne) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_tcp_cong_state_set($arg1, $arg2, (const u8)$arg3)")
  public static void perf_trace_tcp_cong_state_set(Ptr<?> __data, Ptr<sock> sk, char ca_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_tcp_event_sk(Ptr<?> __data, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_tcp_event_skb($arg1, (const struct sk_buff*)$arg2)")
  public static void perf_trace_tcp_event_skb(Ptr<?> __data, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_tcp_hash_event($arg1, (const struct sock*)$arg2, (const struct sk_buff*)$arg3)")
  public static void perf_trace_tcp_hash_event(Ptr<?> __data, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_tcp_probe($arg1, $arg2, (const struct sk_buff*)$arg3)")
  public static void perf_trace_tcp_probe(Ptr<?> __data, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_tcp_rcvbuf_grow(Ptr<?> __data, Ptr<sock> sk, int time) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_tcp_retransmit_skb($arg1, (const struct sock*)$arg2, (const struct sk_buff*)$arg3, $arg4)")
  public static void perf_trace_tcp_retransmit_skb(Ptr<?> __data, Ptr<sock> sk, Ptr<sk_buff> skb,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_tcp_retransmit_synack($arg1, (const struct sock*)$arg2, (const struct request_sock*)$arg3)")
  public static void perf_trace_tcp_retransmit_synack(Ptr<?> __data, Ptr<sock> sk,
      Ptr<request_sock> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_tcp_send_reset($arg1, (const struct sock*)$arg2, (const struct sk_buff*)$arg3, (const enum sk_rst_reason)$arg4)")
  public static void perf_trace_tcp_send_reset(Ptr<?> __data, Ptr<sock> sk,
      Ptr<sk_buff> skb__nullable, sk_rst_reason reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_tcp_sendmsg_locked($arg1, (const struct sock*)$arg2, (const struct msghdr*)$arg3, (const struct sk_buff*)$arg4, $arg5)")
  public static void perf_trace_tcp_sendmsg_locked(Ptr<?> __data, Ptr<sock> sk, Ptr<msghdr> msg,
      Ptr<sk_buff> skb, int size_goal) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_test_pages_isolated(Ptr<?> __data, @Unsigned long start_pfn,
      @Unsigned long end_pfn, @Unsigned long fin_pfn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_thermal_power_actor(Ptr<?> __data, Ptr<thermal_zone_device> tz,
      int actor_id, @Unsigned int req_power, @Unsigned int granted_power) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_thermal_power_allocator(Ptr<?> __data, Ptr<thermal_zone_device> tz,
      @Unsigned int total_req_power, @Unsigned int total_granted_power, int num_actors,
      @Unsigned int power_range, @Unsigned int max_allocatable_power, int current_temp,
      int delta_temp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_thermal_power_allocator_pid(Ptr<?> __data,
      Ptr<thermal_zone_device> tz, int err, int err_integral, long p, long i, long d, int output) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_thermal_power_devfreq_get_power(Ptr<?> __data,
      Ptr<thermal_cooling_device> cdev, Ptr<devfreq_dev_status> status, @Unsigned long freq,
      @Unsigned int power) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_thermal_power_devfreq_limit(Ptr<?> __data,
      Ptr<thermal_cooling_device> cdev, @Unsigned long freq, @Unsigned long cdev_state,
      @Unsigned int power) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_thermal_temperature(Ptr<?> __data, Ptr<thermal_zone_device> tz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_thermal_zone_trip(Ptr<?> __data, Ptr<thermal_zone_device> tz,
      int trip, thermal_trip_type trip_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_thread_noise(Ptr<?> __data, Ptr<task_struct> t,
      @Unsigned long start, @Unsigned long duration) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_tick_stop(Ptr<?> __data, int success, int dependency) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_timer_base_idle(Ptr<?> __data, boolean is_idle, @Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_timer_class(Ptr<?> __data, Ptr<timer_list> timer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_timer_expire_entry(Ptr<?> __data, Ptr<timer_list> timer,
      @Unsigned long baseclk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_timer_start(Ptr<?> __data, Ptr<timer_list> timer,
      @Unsigned long bucket_expiry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_timerlat_sample(Ptr<?> __data, Ptr<timerlat_sample> s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_tlb_flush(Ptr<?> __data, int reason, @Unsigned long pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_tls_contenttype($arg1, (const struct sock*)$arg2, $arg3)")
  public static void perf_trace_tls_contenttype(Ptr<?> __data, Ptr<sock> sk, char type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_tmigr_connect_child_parent(Ptr<?> __data, Ptr<tmigr_group> child) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_tmigr_connect_cpu_parent(Ptr<?> __data, Ptr<tmigr_cpu> tmc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_tmigr_cpugroup(Ptr<?> __data, Ptr<tmigr_cpu> tmc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_tmigr_group_and_cpu(Ptr<?> __data, Ptr<tmigr_group> group,
      tmigr_state state, @Unsigned int childmask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_tmigr_group_set(Ptr<?> __data, Ptr<tmigr_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_tmigr_handle_remote(Ptr<?> __data, Ptr<tmigr_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_tmigr_idle(Ptr<?> __data, Ptr<tmigr_cpu> tmc,
      @Unsigned long nextevt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_tmigr_update_events(Ptr<?> __data, Ptr<tmigr_group> child,
      Ptr<tmigr_group> group, tmigr_state childstate, tmigr_state groupstate,
      @Unsigned long nextevt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_track_foreign_dirty(Ptr<?> __data, Ptr<folio> folio,
      Ptr<bdi_writeback> wb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_tsm_mr_read($arg1, (const struct tsm_measurement_register*)$arg2)")
  public static void perf_trace_tsm_mr_read(Ptr<?> __data, Ptr<tsm_measurement_register> mr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_tsm_mr_refresh($arg1, (const struct tsm_measurement_register*)$arg2, $arg3)")
  public static void perf_trace_tsm_mr_refresh(Ptr<?> __data, Ptr<tsm_measurement_register> mr,
      int rc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_tsm_mr_write($arg1, (const struct tsm_measurement_register*)$arg2, (const u8*)$arg3)")
  public static void perf_trace_tsm_mr_write(Ptr<?> __data, Ptr<tsm_measurement_register> mr,
      Ptr<java.lang.Character> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_udp_fail_queue_rcv_skb(Ptr<?> __data, int rc, Ptr<sock> sk,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_unmap(Ptr<?> __data, @Unsigned long iova, @Unsigned long size,
      @Unsigned long unmapped_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_vector_activate(Ptr<?> __data, @Unsigned int irq,
      boolean is_managed, boolean can_reserve, boolean reserve) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_vector_alloc(Ptr<?> __data, @Unsigned int irq, @Unsigned int vector,
      boolean reserved, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_vector_alloc_managed(Ptr<?> __data, @Unsigned int irq,
      @Unsigned int vector, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_vector_config(Ptr<?> __data, @Unsigned int irq,
      @Unsigned int vector, @Unsigned int cpu, @Unsigned int apicdest) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_vector_free_moved(Ptr<?> __data, @Unsigned int irq,
      @Unsigned int cpu, @Unsigned int vector, boolean is_managed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_vector_mod(Ptr<?> __data, @Unsigned int irq, @Unsigned int vector,
      @Unsigned int cpu, @Unsigned int prev_vector, @Unsigned int prev_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_vector_reserve(Ptr<?> __data, @Unsigned int irq, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_vector_setup(Ptr<?> __data, @Unsigned int irq, boolean is_legacy,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_vector_teardown(Ptr<?> __data, @Unsigned int irq,
      boolean is_managed, boolean has_reserved) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_vm_unmapped_area(Ptr<?> __data, @Unsigned long addr,
      Ptr<vm_unmapped_area_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_wake_reaper(Ptr<?> __data, int pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_wakeup_source($arg1, (const u8*)$arg2, $arg3)")
  public static void perf_trace_wakeup_source(Ptr<?> __data, String name, @Unsigned int state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_watchdog_set_timeout(Ptr<?> __data, Ptr<watchdog_device> wdd,
      @Unsigned int timeout, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_watchdog_template(Ptr<?> __data, Ptr<watchdog_device> wdd,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_wbc_class(Ptr<?> __data, Ptr<writeback_control> wbc,
      Ptr<backing_dev_info> bdi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_wbt_lat(Ptr<?> __data, Ptr<backing_dev_info> bdi,
      @Unsigned long lat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_wbt_stat(Ptr<?> __data, Ptr<backing_dev_info> bdi,
      Ptr<blk_rq_stat> stat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_wbt_step($arg1, $arg2, (const u8*)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void perf_trace_wbt_step(Ptr<?> __data, Ptr<backing_dev_info> bdi, String msg,
      int step, @Unsigned long window, @Unsigned int bg, @Unsigned int normal, @Unsigned int max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_wbt_timer(Ptr<?> __data, Ptr<backing_dev_info> bdi,
      @Unsigned int status, int step, @Unsigned int inflight) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_workqueue_activate_work(Ptr<?> __data, Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_workqueue_execute_end(Ptr<?> __data, Ptr<work_struct> work,
      @OriginalName("work_func_t") Ptr<?> function) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_workqueue_execute_start(Ptr<?> __data, Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_workqueue_queue_work(Ptr<?> __data, int req_cpu,
      Ptr<pool_workqueue> pwq, Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_writeback_bdi_register(Ptr<?> __data, Ptr<backing_dev_info> bdi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_writeback_class(Ptr<?> __data, Ptr<bdi_writeback> wb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_writeback_dirty_inode_template(Ptr<?> __data, Ptr<inode> inode,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_writeback_folio_template(Ptr<?> __data, Ptr<folio> folio,
      Ptr<address_space> mapping) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_writeback_inode_template(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_writeback_pages_written(Ptr<?> __data, long pages_written) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_writeback_queue_io(Ptr<?> __data, Ptr<bdi_writeback> wb,
      Ptr<wb_writeback_work> work, @Unsigned long dirtied_before, int moved) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_writeback_sb_inodes_requeue(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_writeback_single_inode_template(Ptr<?> __data, Ptr<inode> inode,
      Ptr<writeback_control> wbc, @Unsigned long nr_to_write) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_writeback_work_class(Ptr<?> __data, Ptr<bdi_writeback> wb,
      Ptr<wb_writeback_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_writeback_write_inode_template(Ptr<?> __data, Ptr<inode> inode,
      Ptr<writeback_control> wbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_x86_fpu(Ptr<?> __data, Ptr<fpu> fpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_x86_irq_vector(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_xdp_bulk_tx($arg1, (const struct net_device*)$arg2, $arg3, $arg4, $arg5)")
  public static void perf_trace_xdp_bulk_tx(Ptr<?> __data, Ptr<net_device> dev, int sent, int drops,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xdp_cpumap_enqueue(Ptr<?> __data, int map_id,
      @Unsigned int processed, @Unsigned int drops, int to_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xdp_cpumap_kthread(Ptr<?> __data, int map_id,
      @Unsigned int processed, @Unsigned int drops, int sched, Ptr<xdp_cpumap_stats> xdp_stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_xdp_devmap_xmit($arg1, (const struct net_device*)$arg2, (const struct net_device*)$arg3, $arg4, $arg5, $arg6)")
  public static void perf_trace_xdp_devmap_xmit(Ptr<?> __data, Ptr<net_device> from_dev,
      Ptr<net_device> to_dev, int sent, int drops, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_xdp_exception($arg1, (const struct net_device*)$arg2, (const struct bpf_prog*)$arg3, $arg4)")
  public static void perf_trace_xdp_exception(Ptr<?> __data, Ptr<net_device> dev, Ptr<bpf_prog> xdp,
      @Unsigned int act) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_xdp_redirect_template($arg1, (const struct net_device*)$arg2, (const struct bpf_prog*)$arg3, (const void*)$arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void perf_trace_xdp_redirect_template(Ptr<?> __data, Ptr<net_device> dev,
      Ptr<bpf_prog> xdp, Ptr<?> tgt, int err, bpf_map_type map_type, @Unsigned int map_id,
      @Unsigned int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_xen_cpu_load_idt($arg1, (const struct desc_ptr*)$arg2)")
  public static void perf_trace_xen_cpu_load_idt(Ptr<?> __data, Ptr<desc_ptr> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_xen_cpu_set_ldt($arg1, (const void*)$arg2, $arg3)")
  public static void perf_trace_xen_cpu_set_ldt(Ptr<?> __data, Ptr<?> addr, @Unsigned int entries) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_xen_cpu_write_gdt_entry($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static void perf_trace_xen_cpu_write_gdt_entry(Ptr<?> __data, Ptr<desc_struct> dt,
      int entrynum, Ptr<?> desc, int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_xen_cpu_write_idt_entry($arg1, $arg2, $arg3, (const gate_struct*)$arg4)")
  public static void perf_trace_xen_cpu_write_idt_entry(Ptr<?> __data,
      Ptr<@OriginalName("gate_desc") gate_struct> dt, int entrynum,
      Ptr<@OriginalName("gate_desc") gate_struct> ent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xen_cpu_write_ldt_entry(Ptr<?> __data, Ptr<desc_struct> dt,
      int entrynum, @Unsigned long desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xen_mc__batch(Ptr<?> __data, xen_lazy_mode mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xen_mc_callback(Ptr<?> __data,
      @OriginalName("xen_mc_callback_fn_t") Ptr<?> fn, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xen_mc_entry(Ptr<?> __data, Ptr<multicall_entry> mc,
      @Unsigned int nargs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xen_mc_entry_alloc(Ptr<?> __data, @Unsigned long args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xen_mc_extend_args(Ptr<?> __data, @Unsigned long op,
      @Unsigned long args, xen_mc_extend_args res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xen_mc_flush(Ptr<?> __data, @Unsigned int mcidx,
      @Unsigned int argidx, @Unsigned int cbidx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xen_mc_flush_reason(Ptr<?> __data, xen_mc_flush_reason reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xen_mmu__set_pte(Ptr<?> __data, Ptr<pte_t> ptep, pte_t pteval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xen_mmu_alloc_ptpage(Ptr<?> __data, Ptr<mm_struct> mm,
      @Unsigned long pfn, @Unsigned int level, boolean pinned) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("perf_trace_xen_mmu_flush_tlb_multi($arg1, (const struct cpumask*)$arg2, $arg3, $arg4, $arg5)")
  public static void perf_trace_xen_mmu_flush_tlb_multi(Ptr<?> __data, Ptr<cpumask> cpus,
      Ptr<mm_struct> mm, @Unsigned long addr, @Unsigned long end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xen_mmu_flush_tlb_one_user(Ptr<?> __data, @Unsigned long addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xen_mmu_pgd(Ptr<?> __data, Ptr<mm_struct> mm, Ptr<pgd_t> pgd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xen_mmu_ptep_modify_prot(Ptr<?> __data, Ptr<mm_struct> mm,
      @Unsigned long addr, Ptr<pte_t> ptep, pte_t pteval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xen_mmu_release_ptpage(Ptr<?> __data, @Unsigned long pfn,
      @Unsigned int level, boolean pinned) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xen_mmu_set_p4d(Ptr<?> __data, Ptr<p4d_t> p4dp,
      Ptr<p4d_t> user_p4dp, p4d_t p4dval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xen_mmu_set_pmd(Ptr<?> __data, Ptr<pmd_t> pmdp, pmd_t pmdval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xen_mmu_set_pud(Ptr<?> __data, Ptr<pud_t> pudp, pud_t pudval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xen_mmu_write_cr3(Ptr<?> __data, boolean kernel,
      @Unsigned long cr3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xhci_dbc_log_request(Ptr<?> __data, Ptr<dbc_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xhci_log_ctrl_ctx(Ptr<?> __data,
      Ptr<xhci_input_control_ctx> ctrl_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xhci_log_ctx(Ptr<?> __data, Ptr<xhci_hcd> xhci,
      Ptr<xhci_container_ctx> ctx, @Unsigned int ep_num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xhci_log_doorbell(Ptr<?> __data, @Unsigned int slot,
      @Unsigned int doorbell) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xhci_log_ep_ctx(Ptr<?> __data, Ptr<xhci_ep_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xhci_log_free_virt_dev(Ptr<?> __data, Ptr<xhci_virt_device> vdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xhci_log_msg(Ptr<?> __data, Ptr<va_format> vaf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xhci_log_portsc(Ptr<?> __data, Ptr<xhci_port> port,
      @Unsigned int portsc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xhci_log_ring(Ptr<?> __data, Ptr<xhci_ring> ring) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xhci_log_slot_ctx(Ptr<?> __data, Ptr<xhci_slot_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xhci_log_stream_ctx(Ptr<?> __data, Ptr<xhci_stream_info> info,
      @Unsigned int stream_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xhci_log_trb(Ptr<?> __data, Ptr<xhci_ring> ring,
      Ptr<xhci_generic_trb> trb, @Unsigned @OriginalName("dma_addr_t") long dma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xhci_log_urb(Ptr<?> __data, Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_trace_xhci_log_virt_dev(Ptr<?> __data, Ptr<xhci_virt_device> vdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_try_init_event(Ptr<pmu> pmu, Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_unpin_context(Ptr<perf_event_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_unregister_guest_info_callbacks(Ptr<perf_guest_info_callbacks> cbs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void perf_uprobe_destroy(Ptr<perf_event> p_event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_uprobe_event_init(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int perf_uprobe_init(Ptr<perf_event> p_event, @Unsigned long ref_ctr_offset,
      boolean is_retprobe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long perf_virt_to_phys(@Unsigned long virt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_event"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_event extends Struct {
    public list_head event_entry;

    public list_head sibling_list;

    public list_head active_list;

    public rb_node group_node;

    public @Unsigned long group_index;

    public list_head migrate_entry;

    public hlist_node hlist_entry;

    public list_head active_entry;

    public int nr_siblings;

    public int event_caps;

    public int group_caps;

    public @Unsigned int group_generation;

    public Ptr<perf_event> group_leader;

    public Ptr<pmu> pmu;

    public Ptr<?> pmu_private;

    public perf_event_state state;

    public @Unsigned int attach_state;

    public local64_t count;

    public atomic64_t child_count;

    public @Unsigned long total_time_enabled;

    public @Unsigned long total_time_running;

    public @Unsigned long tstamp;

    public perf_event_attr attr;

    public @Unsigned short header_size;

    public @Unsigned short id_header_size;

    public @Unsigned short read_size;

    public hw_perf_event hw;

    public Ptr<perf_event_context> ctx;

    public Ptr<perf_event_pmu_context> pmu_ctx;

    public @OriginalName("atomic_long_t") atomic64_t refcount;

    public atomic64_t child_total_time_enabled;

    public atomic64_t child_total_time_running;

    public mutex child_mutex;

    public list_head child_list;

    public Ptr<perf_event> parent;

    public int oncpu;

    public int cpu;

    public list_head owner_entry;

    public Ptr<task_struct> owner;

    public mutex mmap_mutex;

    public atomic_t mmap_count;

    public Ptr<perf_buffer> rb;

    public list_head rb_entry;

    public @Unsigned long rcu_batches;

    public int rcu_pending;

    public @OriginalName("wait_queue_head_t") wait_queue_head waitq;

    public Ptr<fasync_struct> fasync;

    public @Unsigned int pending_wakeup;

    public @Unsigned int pending_kill;

    public @Unsigned int pending_disable;

    public @Unsigned long pending_addr;

    public irq_work pending_irq;

    public irq_work pending_disable_irq;

    public callback_head pending_task;

    public @Unsigned int pending_work;

    public atomic_t event_limit;

    public perf_addr_filters_head addr_filters;

    public Ptr<perf_addr_filter_range> addr_filter_ranges;

    public @Unsigned long addr_filters_gen;

    public Ptr<perf_event> aux_event;

    public Ptr<?> destroy;

    public callback_head callback_head;

    public Ptr<pid_namespace> ns;

    public @Unsigned long id;

    public atomic64_t lost_samples;

    public Ptr<?> clock;

    public @OriginalName("perf_overflow_handler_t") Ptr<?> overflow_handler;

    public Ptr<?> overflow_handler_context;

    public Ptr<bpf_prog> prog;

    public @Unsigned long bpf_cookie;

    public Ptr<trace_event_call> tp_event;

    public Ptr<event_filter> filter;

    public ftrace_ops ftrace_ops;

    public Ptr<perf_cgroup> cgrp;

    public Ptr<?> security;

    public list_head sb_list;

    public list_head pmu_list;

    public @Unsigned int orig_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long unsigned int _data; unsigned int _type; unsigned int _flags; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class _perf_of_anon_member_of__sigfault_of___sifields extends Struct {
    public @Unsigned long _data;

    public @Unsigned int _type;

    public @Unsigned int _flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_event_context"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_event_context extends Struct {
    public @OriginalName("raw_spinlock_t") raw_spinlock lock;

    public mutex mutex;

    public list_head pmu_ctx_list;

    public perf_event_groups pinned_groups;

    public perf_event_groups flexible_groups;

    public list_head event_list;

    public int nr_events;

    public int nr_user;

    public int is_active;

    public int nr_stat;

    public int nr_freq;

    public int rotate_disable;

    public @OriginalName("refcount_t") refcount_struct refcount;

    public Ptr<task_struct> task;

    public @Unsigned long time;

    public @Unsigned long timestamp;

    public @Unsigned long timeoffset;

    public Ptr<perf_event_context> parent_ctx;

    public @Unsigned long parent_gen;

    public @Unsigned long generation;

    public int pin_count;

    public int nr_cgroups;

    public callback_head callback_head;

    public local_t nr_no_switch_fast;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_ctx_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_ctx_data extends Struct {
    public callback_head callback_head;

    public @OriginalName("refcount_t") refcount_struct refcount;

    public int global;

    public Ptr<kmem_cache> ctx_cache;

    public Ptr<?> data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_event_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_event_attr extends Struct {
    public @Unsigned int type;

    public @Unsigned int size;

    public @Unsigned long config;

    @InlineUnion(1816)
    public @Unsigned long sample_period;

    @InlineUnion(1816)
    public @Unsigned long sample_freq;

    public @Unsigned long sample_type;

    public @Unsigned long read_format;

    public @Unsigned long disabled;

    public @Unsigned long inherit;

    public @Unsigned long pinned;

    public @Unsigned long exclusive;

    public @Unsigned long exclude_user;

    public @Unsigned long exclude_kernel;

    public @Unsigned long exclude_hv;

    public @Unsigned long exclude_idle;

    public @Unsigned long mmap;

    public @Unsigned long comm;

    public @Unsigned long freq;

    public @Unsigned long inherit_stat;

    public @Unsigned long enable_on_exec;

    public @Unsigned long task;

    public @Unsigned long watermark;

    public @Unsigned long precise_ip;

    public @Unsigned long mmap_data;

    public @Unsigned long sample_id_all;

    public @Unsigned long exclude_host;

    public @Unsigned long exclude_guest;

    public @Unsigned long exclude_callchain_kernel;

    public @Unsigned long exclude_callchain_user;

    public @Unsigned long mmap2;

    public @Unsigned long comm_exec;

    public @Unsigned long use_clockid;

    public @Unsigned long context_switch;

    public @Unsigned long write_backward;

    public @Unsigned long namespaces;

    public @Unsigned long ksymbol;

    public @Unsigned long bpf_event;

    public @Unsigned long aux_output;

    public @Unsigned long cgroup;

    public @Unsigned long text_poke;

    public @Unsigned long build_id;

    public @Unsigned long inherit_thread;

    public @Unsigned long remove_on_exec;

    public @Unsigned long sigtrap;

    public @Unsigned long __reserved_1;

    @InlineUnion(1817)
    public @Unsigned int wakeup_events;

    @InlineUnion(1817)
    public @Unsigned int wakeup_watermark;

    public @Unsigned int bp_type;

    @InlineUnion(1818)
    public @Unsigned long bp_addr;

    @InlineUnion(1818)
    public @Unsigned long kprobe_func;

    @InlineUnion(1818)
    public @Unsigned long uprobe_path;

    @InlineUnion(1818)
    public @Unsigned long config1;

    @InlineUnion(1819)
    public @Unsigned long bp_len;

    @InlineUnion(1819)
    public @Unsigned long kprobe_addr;

    @InlineUnion(1819)
    public @Unsigned long probe_offset;

    @InlineUnion(1819)
    public @Unsigned long config2;

    public @Unsigned long branch_sample_type;

    public @Unsigned long sample_regs_user;

    public @Unsigned int sample_stack_user;

    public int clockid;

    public @Unsigned long sample_regs_intr;

    public @Unsigned int aux_watermark;

    public @Unsigned short sample_max_stack;

    public @Unsigned short __reserved_2;

    public @Unsigned int aux_sample_size;

    @InlineUnion(1821)
    public @Unsigned int aux_action;

    @InlineUnion(1821)
    public anon_member_of_anon_member_of_perf_event_attr anon57$1;

    public @Unsigned long sig_data;

    public @Unsigned long config3;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union perf_mem_data_src"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_mem_data_src extends Union {
    public @Unsigned long val;

    public anon_member_of_perf_mem_data_src anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_branch_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_branch_entry extends Struct {
    public @Unsigned long from;

    public @Unsigned long to;

    public @Unsigned long mispred;

    public @Unsigned long predicted;

    public @Unsigned long in_tx;

    public @Unsigned long abort;

    public @Unsigned long cycles;

    public @Unsigned long type;

    public @Unsigned long spec;

    public @Unsigned long new_type;

    public @Unsigned long priv;

    public @Unsigned long reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union perf_sample_weight"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_sample_weight extends Union {
    public @Unsigned long full;

    public anon_member_of_perf_sample_weight anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_regs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_regs extends Struct {
    public @Unsigned long abi;

    public Ptr<pt_regs> regs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int bpf_cookie; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_event_of_anon_member_of_link_create_of_bpf_attr extends Struct {
    public @Unsigned long bpf_cookie;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int type; union { struct { long long unsigned int file_name; unsigned int name_len; unsigned int offset; long long unsigned int cookie; long long unsigned int ref_ctr_offset; } uprobe; struct { long long unsigned int func_name; unsigned int name_len; unsigned int offset; long long unsigned int addr; long long unsigned int missed; long long unsigned int cookie; } kprobe; struct { long long unsigned int tp_name; unsigned int name_len; long long unsigned int cookie; } tracepoint; struct { long long unsigned int config; unsigned int type; long long unsigned int cookie; } event; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_event_of_anon_member_of_bpf_link_info extends Struct {
    public @Unsigned int type;

    @InlineUnion(2016)
    public uprobe_of_anon_member_of_perf_event_of_anon_member_of_bpf_link_info uprobe;

    @InlineUnion(2016)
    public kprobe_of_anon_member_of_perf_event_of_anon_member_of_bpf_link_info kprobe;

    @InlineUnion(2016)
    public tracepoint_of_anon_member_of_perf_event_of_anon_member_of_bpf_link_info tracepoint;

    @InlineUnion(2016)
    public event_of_anon_member_of_perf_event_of_anon_member_of_bpf_link_info event;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_callchain_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_callchain_entry extends Struct {
    public @Unsigned long nr;

    public @Unsigned long @Size(0) [] ip;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_raw_frag"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_raw_frag extends Struct {
    @InlineUnion(2355)
    public Ptr<perf_raw_frag> next;

    @InlineUnion(2355)
    public @Unsigned long pad;

    public @OriginalName("perf_copy_f") Ptr<?> copy;

    public Ptr<?> data;

    public @Unsigned int size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_raw_record"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_raw_record extends Struct {
    public perf_raw_frag frag;

    public @Unsigned int size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_branch_stack"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_branch_stack extends Struct {
    public @Unsigned long nr;

    public @Unsigned long hw_idx;

    public perf_branch_entry @Size(0) [] entries;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_cpu_pmu_context"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_cpu_pmu_context extends Struct {
    public perf_event_pmu_context epc;

    public Ptr<perf_event_pmu_context> task_epc;

    public list_head sched_cb_entry;

    public int sched_cb_usage;

    public int active_oncpu;

    public int exclusive;

    public int pmu_disable_count;

    public @OriginalName("raw_spinlock_t") raw_spinlock hrtimer_lock;

    public hrtimer hrtimer;

    public @OriginalName("ktime_t") long hrtimer_interval;

    public @Unsigned int hrtimer_active;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_event_pmu_context"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_event_pmu_context extends Struct {
    public Ptr<pmu> pmu;

    public Ptr<perf_event_context> ctx;

    public list_head pmu_ctx_entry;

    public list_head pinned_active;

    public list_head flexible_active;

    public @Unsigned int embedded;

    public @Unsigned int nr_events;

    public @Unsigned int nr_cgroups;

    public @Unsigned int nr_freq;

    public atomic_t refcount;

    public callback_head callback_head;

    public int rotate_necessary;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_output_handle"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_output_handle extends Struct {
    public Ptr<perf_event> event;

    public Ptr<perf_buffer> rb;

    public @Unsigned long wakeup;

    public @Unsigned long size;

    @InlineUnion(2425)
    public @Unsigned long flags;

    @InlineUnion(2425)
    public @Unsigned long aux_flags;

    @InlineUnion(2425)
    public anon_member_of_anon_member_of_perf_output_handle anon4$2;

    @InlineUnion(2426)
    public Ptr<?> addr;

    @InlineUnion(2426)
    public @Unsigned long head;

    public int page;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_addr_filters_head"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_addr_filters_head extends Struct {
    public list_head list;

    public @OriginalName("raw_spinlock_t") raw_spinlock lock;

    public @Unsigned int nr_file_filters;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_addr_filter_range"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_addr_filter_range extends Struct {
    public @Unsigned long start;

    public @Unsigned long size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_event_state"
  )
  public enum perf_event_state implements Enum<perf_event_state>, TypedEnum<perf_event_state, java.lang.Integer> {
    /**
     * {@code PERF_EVENT_STATE_DEAD = -5}
     */
    @EnumMember(
        value = -5L,
        name = "PERF_EVENT_STATE_DEAD"
    )
    PERF_EVENT_STATE_DEAD,

    /**
     * {@code PERF_EVENT_STATE_REVOKED = -4}
     */
    @EnumMember(
        value = -4L,
        name = "PERF_EVENT_STATE_REVOKED"
    )
    PERF_EVENT_STATE_REVOKED,

    /**
     * {@code PERF_EVENT_STATE_EXIT = -3}
     */
    @EnumMember(
        value = -3L,
        name = "PERF_EVENT_STATE_EXIT"
    )
    PERF_EVENT_STATE_EXIT,

    /**
     * {@code PERF_EVENT_STATE_ERROR = -2}
     */
    @EnumMember(
        value = -2L,
        name = "PERF_EVENT_STATE_ERROR"
    )
    PERF_EVENT_STATE_ERROR,

    /**
     * {@code PERF_EVENT_STATE_OFF = -1}
     */
    @EnumMember(
        value = -1L,
        name = "PERF_EVENT_STATE_OFF"
    )
    PERF_EVENT_STATE_OFF,

    /**
     * {@code PERF_EVENT_STATE_INACTIVE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PERF_EVENT_STATE_INACTIVE"
    )
    PERF_EVENT_STATE_INACTIVE,

    /**
     * {@code PERF_EVENT_STATE_ACTIVE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PERF_EVENT_STATE_ACTIVE"
    )
    PERF_EVENT_STATE_ACTIVE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_sample_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_sample_data extends Struct {
    public @Unsigned long sample_flags;

    public @Unsigned long period;

    public @Unsigned long dyn_size;

    public @Unsigned long type;

    public tid_entry_of_perf_sample_data tid_entry;

    public @Unsigned long time;

    public @Unsigned long id;

    public cpu_entry_of_perf_sample_data cpu_entry;

    public @Unsigned long ip;

    public Ptr<perf_callchain_entry> callchain;

    public Ptr<perf_raw_record> raw;

    public Ptr<perf_branch_stack> br_stack;

    public Ptr<java.lang. @Unsigned Long> br_stack_cntr;

    public perf_sample_weight weight;

    public perf_mem_data_src data_src;

    public @Unsigned long txn;

    public perf_regs regs_user;

    public perf_regs regs_intr;

    public @Unsigned long stack_user_size;

    public @Unsigned long stream_id;

    public @Unsigned long cgroup;

    public @Unsigned long addr;

    public @Unsigned long phys_addr;

    public @Unsigned long data_page_size;

    public @Unsigned long code_page_size;

    public @Unsigned long aux_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_cgroup"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_cgroup extends Struct {
    public cgroup_subsys_state css;

    public Ptr<perf_cgroup_info> info;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_event_groups"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_event_groups extends Struct {
    public rb_root tree;

    public @Unsigned long index;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_cgroup_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_cgroup_info extends Struct {
    public @Unsigned long time;

    public @Unsigned long timestamp;

    public @Unsigned long timeoffset;

    public int active;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_sw_ids"
  )
  public enum perf_sw_ids implements Enum<perf_sw_ids>, TypedEnum<perf_sw_ids, java.lang. @Unsigned Integer> {
    /**
     * {@code PERF_COUNT_SW_CPU_CLOCK = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PERF_COUNT_SW_CPU_CLOCK"
    )
    PERF_COUNT_SW_CPU_CLOCK,

    /**
     * {@code PERF_COUNT_SW_TASK_CLOCK = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PERF_COUNT_SW_TASK_CLOCK"
    )
    PERF_COUNT_SW_TASK_CLOCK,

    /**
     * {@code PERF_COUNT_SW_PAGE_FAULTS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PERF_COUNT_SW_PAGE_FAULTS"
    )
    PERF_COUNT_SW_PAGE_FAULTS,

    /**
     * {@code PERF_COUNT_SW_CONTEXT_SWITCHES = 3}
     */
    @EnumMember(
        value = 3L,
        name = "PERF_COUNT_SW_CONTEXT_SWITCHES"
    )
    PERF_COUNT_SW_CONTEXT_SWITCHES,

    /**
     * {@code PERF_COUNT_SW_CPU_MIGRATIONS = 4}
     */
    @EnumMember(
        value = 4L,
        name = "PERF_COUNT_SW_CPU_MIGRATIONS"
    )
    PERF_COUNT_SW_CPU_MIGRATIONS,

    /**
     * {@code PERF_COUNT_SW_PAGE_FAULTS_MIN = 5}
     */
    @EnumMember(
        value = 5L,
        name = "PERF_COUNT_SW_PAGE_FAULTS_MIN"
    )
    PERF_COUNT_SW_PAGE_FAULTS_MIN,

    /**
     * {@code PERF_COUNT_SW_PAGE_FAULTS_MAJ = 6}
     */
    @EnumMember(
        value = 6L,
        name = "PERF_COUNT_SW_PAGE_FAULTS_MAJ"
    )
    PERF_COUNT_SW_PAGE_FAULTS_MAJ,

    /**
     * {@code PERF_COUNT_SW_ALIGNMENT_FAULTS = 7}
     */
    @EnumMember(
        value = 7L,
        name = "PERF_COUNT_SW_ALIGNMENT_FAULTS"
    )
    PERF_COUNT_SW_ALIGNMENT_FAULTS,

    /**
     * {@code PERF_COUNT_SW_EMULATION_FAULTS = 8}
     */
    @EnumMember(
        value = 8L,
        name = "PERF_COUNT_SW_EMULATION_FAULTS"
    )
    PERF_COUNT_SW_EMULATION_FAULTS,

    /**
     * {@code PERF_COUNT_SW_DUMMY = 9}
     */
    @EnumMember(
        value = 9L,
        name = "PERF_COUNT_SW_DUMMY"
    )
    PERF_COUNT_SW_DUMMY,

    /**
     * {@code PERF_COUNT_SW_BPF_OUTPUT = 10}
     */
    @EnumMember(
        value = 10L,
        name = "PERF_COUNT_SW_BPF_OUTPUT"
    )
    PERF_COUNT_SW_BPF_OUTPUT,

    /**
     * {@code PERF_COUNT_SW_CGROUP_SWITCHES = 11}
     */
    @EnumMember(
        value = 11L,
        name = "PERF_COUNT_SW_CGROUP_SWITCHES"
    )
    PERF_COUNT_SW_CGROUP_SWITCHES,

    /**
     * {@code PERF_COUNT_SW_MAX = 12}
     */
    @EnumMember(
        value = 12L,
        name = "PERF_COUNT_SW_MAX"
    )
    PERF_COUNT_SW_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_branch_sample_type_shift"
  )
  public enum perf_branch_sample_type_shift implements Enum<perf_branch_sample_type_shift>, TypedEnum<perf_branch_sample_type_shift, java.lang. @Unsigned Integer> {
    /**
     * {@code PERF_SAMPLE_BRANCH_USER_SHIFT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PERF_SAMPLE_BRANCH_USER_SHIFT"
    )
    PERF_SAMPLE_BRANCH_USER_SHIFT,

    /**
     * {@code PERF_SAMPLE_BRANCH_KERNEL_SHIFT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PERF_SAMPLE_BRANCH_KERNEL_SHIFT"
    )
    PERF_SAMPLE_BRANCH_KERNEL_SHIFT,

    /**
     * {@code PERF_SAMPLE_BRANCH_HV_SHIFT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PERF_SAMPLE_BRANCH_HV_SHIFT"
    )
    PERF_SAMPLE_BRANCH_HV_SHIFT,

    /**
     * {@code PERF_SAMPLE_BRANCH_ANY_SHIFT = 3}
     */
    @EnumMember(
        value = 3L,
        name = "PERF_SAMPLE_BRANCH_ANY_SHIFT"
    )
    PERF_SAMPLE_BRANCH_ANY_SHIFT,

    /**
     * {@code PERF_SAMPLE_BRANCH_ANY_CALL_SHIFT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "PERF_SAMPLE_BRANCH_ANY_CALL_SHIFT"
    )
    PERF_SAMPLE_BRANCH_ANY_CALL_SHIFT,

    /**
     * {@code PERF_SAMPLE_BRANCH_ANY_RETURN_SHIFT = 5}
     */
    @EnumMember(
        value = 5L,
        name = "PERF_SAMPLE_BRANCH_ANY_RETURN_SHIFT"
    )
    PERF_SAMPLE_BRANCH_ANY_RETURN_SHIFT,

    /**
     * {@code PERF_SAMPLE_BRANCH_IND_CALL_SHIFT = 6}
     */
    @EnumMember(
        value = 6L,
        name = "PERF_SAMPLE_BRANCH_IND_CALL_SHIFT"
    )
    PERF_SAMPLE_BRANCH_IND_CALL_SHIFT,

    /**
     * {@code PERF_SAMPLE_BRANCH_ABORT_TX_SHIFT = 7}
     */
    @EnumMember(
        value = 7L,
        name = "PERF_SAMPLE_BRANCH_ABORT_TX_SHIFT"
    )
    PERF_SAMPLE_BRANCH_ABORT_TX_SHIFT,

    /**
     * {@code PERF_SAMPLE_BRANCH_IN_TX_SHIFT = 8}
     */
    @EnumMember(
        value = 8L,
        name = "PERF_SAMPLE_BRANCH_IN_TX_SHIFT"
    )
    PERF_SAMPLE_BRANCH_IN_TX_SHIFT,

    /**
     * {@code PERF_SAMPLE_BRANCH_NO_TX_SHIFT = 9}
     */
    @EnumMember(
        value = 9L,
        name = "PERF_SAMPLE_BRANCH_NO_TX_SHIFT"
    )
    PERF_SAMPLE_BRANCH_NO_TX_SHIFT,

    /**
     * {@code PERF_SAMPLE_BRANCH_COND_SHIFT = 10}
     */
    @EnumMember(
        value = 10L,
        name = "PERF_SAMPLE_BRANCH_COND_SHIFT"
    )
    PERF_SAMPLE_BRANCH_COND_SHIFT,

    /**
     * {@code PERF_SAMPLE_BRANCH_CALL_STACK_SHIFT = 11}
     */
    @EnumMember(
        value = 11L,
        name = "PERF_SAMPLE_BRANCH_CALL_STACK_SHIFT"
    )
    PERF_SAMPLE_BRANCH_CALL_STACK_SHIFT,

    /**
     * {@code PERF_SAMPLE_BRANCH_IND_JUMP_SHIFT = 12}
     */
    @EnumMember(
        value = 12L,
        name = "PERF_SAMPLE_BRANCH_IND_JUMP_SHIFT"
    )
    PERF_SAMPLE_BRANCH_IND_JUMP_SHIFT,

    /**
     * {@code PERF_SAMPLE_BRANCH_CALL_SHIFT = 13}
     */
    @EnumMember(
        value = 13L,
        name = "PERF_SAMPLE_BRANCH_CALL_SHIFT"
    )
    PERF_SAMPLE_BRANCH_CALL_SHIFT,

    /**
     * {@code PERF_SAMPLE_BRANCH_NO_FLAGS_SHIFT = 14}
     */
    @EnumMember(
        value = 14L,
        name = "PERF_SAMPLE_BRANCH_NO_FLAGS_SHIFT"
    )
    PERF_SAMPLE_BRANCH_NO_FLAGS_SHIFT,

    /**
     * {@code PERF_SAMPLE_BRANCH_NO_CYCLES_SHIFT = 15}
     */
    @EnumMember(
        value = 15L,
        name = "PERF_SAMPLE_BRANCH_NO_CYCLES_SHIFT"
    )
    PERF_SAMPLE_BRANCH_NO_CYCLES_SHIFT,

    /**
     * {@code PERF_SAMPLE_BRANCH_TYPE_SAVE_SHIFT = 16}
     */
    @EnumMember(
        value = 16L,
        name = "PERF_SAMPLE_BRANCH_TYPE_SAVE_SHIFT"
    )
    PERF_SAMPLE_BRANCH_TYPE_SAVE_SHIFT,

    /**
     * {@code PERF_SAMPLE_BRANCH_HW_INDEX_SHIFT = 17}
     */
    @EnumMember(
        value = 17L,
        name = "PERF_SAMPLE_BRANCH_HW_INDEX_SHIFT"
    )
    PERF_SAMPLE_BRANCH_HW_INDEX_SHIFT,

    /**
     * {@code PERF_SAMPLE_BRANCH_PRIV_SAVE_SHIFT = 18}
     */
    @EnumMember(
        value = 18L,
        name = "PERF_SAMPLE_BRANCH_PRIV_SAVE_SHIFT"
    )
    PERF_SAMPLE_BRANCH_PRIV_SAVE_SHIFT,

    /**
     * {@code PERF_SAMPLE_BRANCH_COUNTERS_SHIFT = 19}
     */
    @EnumMember(
        value = 19L,
        name = "PERF_SAMPLE_BRANCH_COUNTERS_SHIFT"
    )
    PERF_SAMPLE_BRANCH_COUNTERS_SHIFT,

    /**
     * {@code PERF_SAMPLE_BRANCH_MAX_SHIFT = 20}
     */
    @EnumMember(
        value = 20L,
        name = "PERF_SAMPLE_BRANCH_MAX_SHIFT"
    )
    PERF_SAMPLE_BRANCH_MAX_SHIFT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_type_id"
  )
  public enum perf_type_id implements Enum<perf_type_id>, TypedEnum<perf_type_id, java.lang. @Unsigned Integer> {
    /**
     * {@code PERF_TYPE_HARDWARE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PERF_TYPE_HARDWARE"
    )
    PERF_TYPE_HARDWARE,

    /**
     * {@code PERF_TYPE_SOFTWARE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PERF_TYPE_SOFTWARE"
    )
    PERF_TYPE_SOFTWARE,

    /**
     * {@code PERF_TYPE_TRACEPOINT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PERF_TYPE_TRACEPOINT"
    )
    PERF_TYPE_TRACEPOINT,

    /**
     * {@code PERF_TYPE_HW_CACHE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "PERF_TYPE_HW_CACHE"
    )
    PERF_TYPE_HW_CACHE,

    /**
     * {@code PERF_TYPE_RAW = 4}
     */
    @EnumMember(
        value = 4L,
        name = "PERF_TYPE_RAW"
    )
    PERF_TYPE_RAW,

    /**
     * {@code PERF_TYPE_BREAKPOINT = 5}
     */
    @EnumMember(
        value = 5L,
        name = "PERF_TYPE_BREAKPOINT"
    )
    PERF_TYPE_BREAKPOINT,

    /**
     * {@code PERF_TYPE_MAX = 6}
     */
    @EnumMember(
        value = 6L,
        name = "PERF_TYPE_MAX"
    )
    PERF_TYPE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_hw_id"
  )
  public enum perf_hw_id implements Enum<perf_hw_id>, TypedEnum<perf_hw_id, java.lang. @Unsigned Integer> {
    /**
     * {@code PERF_COUNT_HW_CPU_CYCLES = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PERF_COUNT_HW_CPU_CYCLES"
    )
    PERF_COUNT_HW_CPU_CYCLES,

    /**
     * {@code PERF_COUNT_HW_INSTRUCTIONS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PERF_COUNT_HW_INSTRUCTIONS"
    )
    PERF_COUNT_HW_INSTRUCTIONS,

    /**
     * {@code PERF_COUNT_HW_CACHE_REFERENCES = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PERF_COUNT_HW_CACHE_REFERENCES"
    )
    PERF_COUNT_HW_CACHE_REFERENCES,

    /**
     * {@code PERF_COUNT_HW_CACHE_MISSES = 3}
     */
    @EnumMember(
        value = 3L,
        name = "PERF_COUNT_HW_CACHE_MISSES"
    )
    PERF_COUNT_HW_CACHE_MISSES,

    /**
     * {@code PERF_COUNT_HW_BRANCH_INSTRUCTIONS = 4}
     */
    @EnumMember(
        value = 4L,
        name = "PERF_COUNT_HW_BRANCH_INSTRUCTIONS"
    )
    PERF_COUNT_HW_BRANCH_INSTRUCTIONS,

    /**
     * {@code PERF_COUNT_HW_BRANCH_MISSES = 5}
     */
    @EnumMember(
        value = 5L,
        name = "PERF_COUNT_HW_BRANCH_MISSES"
    )
    PERF_COUNT_HW_BRANCH_MISSES,

    /**
     * {@code PERF_COUNT_HW_BUS_CYCLES = 6}
     */
    @EnumMember(
        value = 6L,
        name = "PERF_COUNT_HW_BUS_CYCLES"
    )
    PERF_COUNT_HW_BUS_CYCLES,

    /**
     * {@code PERF_COUNT_HW_STALLED_CYCLES_FRONTEND = 7}
     */
    @EnumMember(
        value = 7L,
        name = "PERF_COUNT_HW_STALLED_CYCLES_FRONTEND"
    )
    PERF_COUNT_HW_STALLED_CYCLES_FRONTEND,

    /**
     * {@code PERF_COUNT_HW_STALLED_CYCLES_BACKEND = 8}
     */
    @EnumMember(
        value = 8L,
        name = "PERF_COUNT_HW_STALLED_CYCLES_BACKEND"
    )
    PERF_COUNT_HW_STALLED_CYCLES_BACKEND,

    /**
     * {@code PERF_COUNT_HW_REF_CPU_CYCLES = 9}
     */
    @EnumMember(
        value = 9L,
        name = "PERF_COUNT_HW_REF_CPU_CYCLES"
    )
    PERF_COUNT_HW_REF_CPU_CYCLES,

    /**
     * {@code PERF_COUNT_HW_MAX = 10}
     */
    @EnumMember(
        value = 10L,
        name = "PERF_COUNT_HW_MAX"
    )
    PERF_COUNT_HW_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_hw_cache_id"
  )
  public enum perf_hw_cache_id implements Enum<perf_hw_cache_id>, TypedEnum<perf_hw_cache_id, java.lang. @Unsigned Integer> {
    /**
     * {@code PERF_COUNT_HW_CACHE_L1D = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PERF_COUNT_HW_CACHE_L1D"
    )
    PERF_COUNT_HW_CACHE_L1D,

    /**
     * {@code PERF_COUNT_HW_CACHE_L1I = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PERF_COUNT_HW_CACHE_L1I"
    )
    PERF_COUNT_HW_CACHE_L1I,

    /**
     * {@code PERF_COUNT_HW_CACHE_LL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PERF_COUNT_HW_CACHE_LL"
    )
    PERF_COUNT_HW_CACHE_LL,

    /**
     * {@code PERF_COUNT_HW_CACHE_DTLB = 3}
     */
    @EnumMember(
        value = 3L,
        name = "PERF_COUNT_HW_CACHE_DTLB"
    )
    PERF_COUNT_HW_CACHE_DTLB,

    /**
     * {@code PERF_COUNT_HW_CACHE_ITLB = 4}
     */
    @EnumMember(
        value = 4L,
        name = "PERF_COUNT_HW_CACHE_ITLB"
    )
    PERF_COUNT_HW_CACHE_ITLB,

    /**
     * {@code PERF_COUNT_HW_CACHE_BPU = 5}
     */
    @EnumMember(
        value = 5L,
        name = "PERF_COUNT_HW_CACHE_BPU"
    )
    PERF_COUNT_HW_CACHE_BPU,

    /**
     * {@code PERF_COUNT_HW_CACHE_NODE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "PERF_COUNT_HW_CACHE_NODE"
    )
    PERF_COUNT_HW_CACHE_NODE,

    /**
     * {@code PERF_COUNT_HW_CACHE_MAX = 7}
     */
    @EnumMember(
        value = 7L,
        name = "PERF_COUNT_HW_CACHE_MAX"
    )
    PERF_COUNT_HW_CACHE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_hw_cache_op_id"
  )
  public enum perf_hw_cache_op_id implements Enum<perf_hw_cache_op_id>, TypedEnum<perf_hw_cache_op_id, java.lang. @Unsigned Integer> {
    /**
     * {@code PERF_COUNT_HW_CACHE_OP_READ = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PERF_COUNT_HW_CACHE_OP_READ"
    )
    PERF_COUNT_HW_CACHE_OP_READ,

    /**
     * {@code PERF_COUNT_HW_CACHE_OP_WRITE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PERF_COUNT_HW_CACHE_OP_WRITE"
    )
    PERF_COUNT_HW_CACHE_OP_WRITE,

    /**
     * {@code PERF_COUNT_HW_CACHE_OP_PREFETCH = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PERF_COUNT_HW_CACHE_OP_PREFETCH"
    )
    PERF_COUNT_HW_CACHE_OP_PREFETCH,

    /**
     * {@code PERF_COUNT_HW_CACHE_OP_MAX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "PERF_COUNT_HW_CACHE_OP_MAX"
    )
    PERF_COUNT_HW_CACHE_OP_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_hw_cache_op_result_id"
  )
  public enum perf_hw_cache_op_result_id implements Enum<perf_hw_cache_op_result_id>, TypedEnum<perf_hw_cache_op_result_id, java.lang. @Unsigned Integer> {
    /**
     * {@code PERF_COUNT_HW_CACHE_RESULT_ACCESS = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PERF_COUNT_HW_CACHE_RESULT_ACCESS"
    )
    PERF_COUNT_HW_CACHE_RESULT_ACCESS,

    /**
     * {@code PERF_COUNT_HW_CACHE_RESULT_MISS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PERF_COUNT_HW_CACHE_RESULT_MISS"
    )
    PERF_COUNT_HW_CACHE_RESULT_MISS,

    /**
     * {@code PERF_COUNT_HW_CACHE_RESULT_MAX = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PERF_COUNT_HW_CACHE_RESULT_MAX"
    )
    PERF_COUNT_HW_CACHE_RESULT_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_event_sample_format"
  )
  public enum perf_event_sample_format implements Enum<perf_event_sample_format>, TypedEnum<perf_event_sample_format, java.lang. @Unsigned Integer> {
    /**
     * {@code PERF_SAMPLE_IP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PERF_SAMPLE_IP"
    )
    PERF_SAMPLE_IP,

    /**
     * {@code PERF_SAMPLE_TID = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PERF_SAMPLE_TID"
    )
    PERF_SAMPLE_TID,

    /**
     * {@code PERF_SAMPLE_TIME = 4}
     */
    @EnumMember(
        value = 4L,
        name = "PERF_SAMPLE_TIME"
    )
    PERF_SAMPLE_TIME,

    /**
     * {@code PERF_SAMPLE_ADDR = 8}
     */
    @EnumMember(
        value = 8L,
        name = "PERF_SAMPLE_ADDR"
    )
    PERF_SAMPLE_ADDR,

    /**
     * {@code PERF_SAMPLE_READ = 16}
     */
    @EnumMember(
        value = 16L,
        name = "PERF_SAMPLE_READ"
    )
    PERF_SAMPLE_READ,

    /**
     * {@code PERF_SAMPLE_CALLCHAIN = 32}
     */
    @EnumMember(
        value = 32L,
        name = "PERF_SAMPLE_CALLCHAIN"
    )
    PERF_SAMPLE_CALLCHAIN,

    /**
     * {@code PERF_SAMPLE_ID = 64}
     */
    @EnumMember(
        value = 64L,
        name = "PERF_SAMPLE_ID"
    )
    PERF_SAMPLE_ID,

    /**
     * {@code PERF_SAMPLE_CPU = 128}
     */
    @EnumMember(
        value = 128L,
        name = "PERF_SAMPLE_CPU"
    )
    PERF_SAMPLE_CPU,

    /**
     * {@code PERF_SAMPLE_PERIOD = 256}
     */
    @EnumMember(
        value = 256L,
        name = "PERF_SAMPLE_PERIOD"
    )
    PERF_SAMPLE_PERIOD,

    /**
     * {@code PERF_SAMPLE_STREAM_ID = 512}
     */
    @EnumMember(
        value = 512L,
        name = "PERF_SAMPLE_STREAM_ID"
    )
    PERF_SAMPLE_STREAM_ID,

    /**
     * {@code PERF_SAMPLE_RAW = 1024}
     */
    @EnumMember(
        value = 1024L,
        name = "PERF_SAMPLE_RAW"
    )
    PERF_SAMPLE_RAW,

    /**
     * {@code PERF_SAMPLE_BRANCH_STACK = 2048}
     */
    @EnumMember(
        value = 2048L,
        name = "PERF_SAMPLE_BRANCH_STACK"
    )
    PERF_SAMPLE_BRANCH_STACK,

    /**
     * {@code PERF_SAMPLE_REGS_USER = 4096}
     */
    @EnumMember(
        value = 4096L,
        name = "PERF_SAMPLE_REGS_USER"
    )
    PERF_SAMPLE_REGS_USER,

    /**
     * {@code PERF_SAMPLE_STACK_USER = 8192}
     */
    @EnumMember(
        value = 8192L,
        name = "PERF_SAMPLE_STACK_USER"
    )
    PERF_SAMPLE_STACK_USER,

    /**
     * {@code PERF_SAMPLE_WEIGHT = 16384}
     */
    @EnumMember(
        value = 16384L,
        name = "PERF_SAMPLE_WEIGHT"
    )
    PERF_SAMPLE_WEIGHT,

    /**
     * {@code PERF_SAMPLE_DATA_SRC = 32768}
     */
    @EnumMember(
        value = 32768L,
        name = "PERF_SAMPLE_DATA_SRC"
    )
    PERF_SAMPLE_DATA_SRC,

    /**
     * {@code PERF_SAMPLE_IDENTIFIER = 65536}
     */
    @EnumMember(
        value = 65536L,
        name = "PERF_SAMPLE_IDENTIFIER"
    )
    PERF_SAMPLE_IDENTIFIER,

    /**
     * {@code PERF_SAMPLE_TRANSACTION = 131072}
     */
    @EnumMember(
        value = 131072L,
        name = "PERF_SAMPLE_TRANSACTION"
    )
    PERF_SAMPLE_TRANSACTION,

    /**
     * {@code PERF_SAMPLE_REGS_INTR = 262144}
     */
    @EnumMember(
        value = 262144L,
        name = "PERF_SAMPLE_REGS_INTR"
    )
    PERF_SAMPLE_REGS_INTR,

    /**
     * {@code PERF_SAMPLE_PHYS_ADDR = 524288}
     */
    @EnumMember(
        value = 524288L,
        name = "PERF_SAMPLE_PHYS_ADDR"
    )
    PERF_SAMPLE_PHYS_ADDR,

    /**
     * {@code PERF_SAMPLE_AUX = 1048576}
     */
    @EnumMember(
        value = 1048576L,
        name = "PERF_SAMPLE_AUX"
    )
    PERF_SAMPLE_AUX,

    /**
     * {@code PERF_SAMPLE_CGROUP = 2097152}
     */
    @EnumMember(
        value = 2097152L,
        name = "PERF_SAMPLE_CGROUP"
    )
    PERF_SAMPLE_CGROUP,

    /**
     * {@code PERF_SAMPLE_DATA_PAGE_SIZE = 4194304}
     */
    @EnumMember(
        value = 4194304L,
        name = "PERF_SAMPLE_DATA_PAGE_SIZE"
    )
    PERF_SAMPLE_DATA_PAGE_SIZE,

    /**
     * {@code PERF_SAMPLE_CODE_PAGE_SIZE = 8388608}
     */
    @EnumMember(
        value = 8388608L,
        name = "PERF_SAMPLE_CODE_PAGE_SIZE"
    )
    PERF_SAMPLE_CODE_PAGE_SIZE,

    /**
     * {@code PERF_SAMPLE_WEIGHT_STRUCT = 16777216}
     */
    @EnumMember(
        value = 16777216L,
        name = "PERF_SAMPLE_WEIGHT_STRUCT"
    )
    PERF_SAMPLE_WEIGHT_STRUCT,

    /**
     * {@code PERF_SAMPLE_MAX = 33554432}
     */
    @EnumMember(
        value = 33554432L,
        name = "PERF_SAMPLE_MAX"
    )
    PERF_SAMPLE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_branch_sample_type"
  )
  public enum perf_branch_sample_type implements Enum<perf_branch_sample_type>, TypedEnum<perf_branch_sample_type, java.lang. @Unsigned Integer> {
    /**
     * {@code PERF_SAMPLE_BRANCH_USER = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PERF_SAMPLE_BRANCH_USER"
    )
    PERF_SAMPLE_BRANCH_USER,

    /**
     * {@code PERF_SAMPLE_BRANCH_KERNEL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PERF_SAMPLE_BRANCH_KERNEL"
    )
    PERF_SAMPLE_BRANCH_KERNEL,

    /**
     * {@code PERF_SAMPLE_BRANCH_HV = 4}
     */
    @EnumMember(
        value = 4L,
        name = "PERF_SAMPLE_BRANCH_HV"
    )
    PERF_SAMPLE_BRANCH_HV,

    /**
     * {@code PERF_SAMPLE_BRANCH_ANY = 8}
     */
    @EnumMember(
        value = 8L,
        name = "PERF_SAMPLE_BRANCH_ANY"
    )
    PERF_SAMPLE_BRANCH_ANY,

    /**
     * {@code PERF_SAMPLE_BRANCH_ANY_CALL = 16}
     */
    @EnumMember(
        value = 16L,
        name = "PERF_SAMPLE_BRANCH_ANY_CALL"
    )
    PERF_SAMPLE_BRANCH_ANY_CALL,

    /**
     * {@code PERF_SAMPLE_BRANCH_ANY_RETURN = 32}
     */
    @EnumMember(
        value = 32L,
        name = "PERF_SAMPLE_BRANCH_ANY_RETURN"
    )
    PERF_SAMPLE_BRANCH_ANY_RETURN,

    /**
     * {@code PERF_SAMPLE_BRANCH_IND_CALL = 64}
     */
    @EnumMember(
        value = 64L,
        name = "PERF_SAMPLE_BRANCH_IND_CALL"
    )
    PERF_SAMPLE_BRANCH_IND_CALL,

    /**
     * {@code PERF_SAMPLE_BRANCH_ABORT_TX = 128}
     */
    @EnumMember(
        value = 128L,
        name = "PERF_SAMPLE_BRANCH_ABORT_TX"
    )
    PERF_SAMPLE_BRANCH_ABORT_TX,

    /**
     * {@code PERF_SAMPLE_BRANCH_IN_TX = 256}
     */
    @EnumMember(
        value = 256L,
        name = "PERF_SAMPLE_BRANCH_IN_TX"
    )
    PERF_SAMPLE_BRANCH_IN_TX,

    /**
     * {@code PERF_SAMPLE_BRANCH_NO_TX = 512}
     */
    @EnumMember(
        value = 512L,
        name = "PERF_SAMPLE_BRANCH_NO_TX"
    )
    PERF_SAMPLE_BRANCH_NO_TX,

    /**
     * {@code PERF_SAMPLE_BRANCH_COND = 1024}
     */
    @EnumMember(
        value = 1024L,
        name = "PERF_SAMPLE_BRANCH_COND"
    )
    PERF_SAMPLE_BRANCH_COND,

    /**
     * {@code PERF_SAMPLE_BRANCH_CALL_STACK = 2048}
     */
    @EnumMember(
        value = 2048L,
        name = "PERF_SAMPLE_BRANCH_CALL_STACK"
    )
    PERF_SAMPLE_BRANCH_CALL_STACK,

    /**
     * {@code PERF_SAMPLE_BRANCH_IND_JUMP = 4096}
     */
    @EnumMember(
        value = 4096L,
        name = "PERF_SAMPLE_BRANCH_IND_JUMP"
    )
    PERF_SAMPLE_BRANCH_IND_JUMP,

    /**
     * {@code PERF_SAMPLE_BRANCH_CALL = 8192}
     */
    @EnumMember(
        value = 8192L,
        name = "PERF_SAMPLE_BRANCH_CALL"
    )
    PERF_SAMPLE_BRANCH_CALL,

    /**
     * {@code PERF_SAMPLE_BRANCH_NO_FLAGS = 16384}
     */
    @EnumMember(
        value = 16384L,
        name = "PERF_SAMPLE_BRANCH_NO_FLAGS"
    )
    PERF_SAMPLE_BRANCH_NO_FLAGS,

    /**
     * {@code PERF_SAMPLE_BRANCH_NO_CYCLES = 32768}
     */
    @EnumMember(
        value = 32768L,
        name = "PERF_SAMPLE_BRANCH_NO_CYCLES"
    )
    PERF_SAMPLE_BRANCH_NO_CYCLES,

    /**
     * {@code PERF_SAMPLE_BRANCH_TYPE_SAVE = 65536}
     */
    @EnumMember(
        value = 65536L,
        name = "PERF_SAMPLE_BRANCH_TYPE_SAVE"
    )
    PERF_SAMPLE_BRANCH_TYPE_SAVE,

    /**
     * {@code PERF_SAMPLE_BRANCH_HW_INDEX = 131072}
     */
    @EnumMember(
        value = 131072L,
        name = "PERF_SAMPLE_BRANCH_HW_INDEX"
    )
    PERF_SAMPLE_BRANCH_HW_INDEX,

    /**
     * {@code PERF_SAMPLE_BRANCH_PRIV_SAVE = 262144}
     */
    @EnumMember(
        value = 262144L,
        name = "PERF_SAMPLE_BRANCH_PRIV_SAVE"
    )
    PERF_SAMPLE_BRANCH_PRIV_SAVE,

    /**
     * {@code PERF_SAMPLE_BRANCH_COUNTERS = 524288}
     */
    @EnumMember(
        value = 524288L,
        name = "PERF_SAMPLE_BRANCH_COUNTERS"
    )
    PERF_SAMPLE_BRANCH_COUNTERS,

    /**
     * {@code PERF_SAMPLE_BRANCH_MAX = 1048576}
     */
    @EnumMember(
        value = 1048576L,
        name = "PERF_SAMPLE_BRANCH_MAX"
    )
    PERF_SAMPLE_BRANCH_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_event_mmap_page"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_event_mmap_page extends Struct {
    public @Unsigned int version;

    public @Unsigned int compat_version;

    public @Unsigned int lock;

    public @Unsigned int index;

    public long offset;

    public @Unsigned long time_enabled;

    public @Unsigned long time_running;

    @InlineUnion(4559)
    public @Unsigned long capabilities;

    @InlineUnion(4559)
    public anon_member_of_anon_member_of_perf_event_mmap_page anon7$1;

    public @Unsigned short pmc_width;

    public @Unsigned short time_shift;

    public @Unsigned int time_mult;

    public @Unsigned long time_offset;

    public @Unsigned long time_zero;

    public @Unsigned int size;

    public @Unsigned int __reserved_1;

    public @Unsigned long time_cycles;

    public @Unsigned long time_mask;

    public char @Size(928) [] __reserved;

    public @Unsigned long data_head;

    public @Unsigned long data_tail;

    public @Unsigned long data_offset;

    public @Unsigned long data_size;

    public @Unsigned long aux_head;

    public @Unsigned long aux_tail;

    public @Unsigned long aux_offset;

    public @Unsigned long aux_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_guest_switch_msr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_guest_switch_msr extends Struct {
    public @Unsigned int msr;

    public @Unsigned long host;

    public @Unsigned long guest;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_event_x86_regs"
  )
  public enum perf_event_x86_regs implements Enum<perf_event_x86_regs>, TypedEnum<perf_event_x86_regs, java.lang. @Unsigned Integer> {
    /**
     * {@code PERF_REG_X86_AX = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PERF_REG_X86_AX"
    )
    PERF_REG_X86_AX,

    /**
     * {@code PERF_REG_X86_BX = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PERF_REG_X86_BX"
    )
    PERF_REG_X86_BX,

    /**
     * {@code PERF_REG_X86_CX = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PERF_REG_X86_CX"
    )
    PERF_REG_X86_CX,

    /**
     * {@code PERF_REG_X86_DX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "PERF_REG_X86_DX"
    )
    PERF_REG_X86_DX,

    /**
     * {@code PERF_REG_X86_SI = 4}
     */
    @EnumMember(
        value = 4L,
        name = "PERF_REG_X86_SI"
    )
    PERF_REG_X86_SI,

    /**
     * {@code PERF_REG_X86_DI = 5}
     */
    @EnumMember(
        value = 5L,
        name = "PERF_REG_X86_DI"
    )
    PERF_REG_X86_DI,

    /**
     * {@code PERF_REG_X86_BP = 6}
     */
    @EnumMember(
        value = 6L,
        name = "PERF_REG_X86_BP"
    )
    PERF_REG_X86_BP,

    /**
     * {@code PERF_REG_X86_SP = 7}
     */
    @EnumMember(
        value = 7L,
        name = "PERF_REG_X86_SP"
    )
    PERF_REG_X86_SP,

    /**
     * {@code PERF_REG_X86_IP = 8}
     */
    @EnumMember(
        value = 8L,
        name = "PERF_REG_X86_IP"
    )
    PERF_REG_X86_IP,

    /**
     * {@code PERF_REG_X86_FLAGS = 9}
     */
    @EnumMember(
        value = 9L,
        name = "PERF_REG_X86_FLAGS"
    )
    PERF_REG_X86_FLAGS,

    /**
     * {@code PERF_REG_X86_CS = 10}
     */
    @EnumMember(
        value = 10L,
        name = "PERF_REG_X86_CS"
    )
    PERF_REG_X86_CS,

    /**
     * {@code PERF_REG_X86_SS = 11}
     */
    @EnumMember(
        value = 11L,
        name = "PERF_REG_X86_SS"
    )
    PERF_REG_X86_SS,

    /**
     * {@code PERF_REG_X86_DS = 12}
     */
    @EnumMember(
        value = 12L,
        name = "PERF_REG_X86_DS"
    )
    PERF_REG_X86_DS,

    /**
     * {@code PERF_REG_X86_ES = 13}
     */
    @EnumMember(
        value = 13L,
        name = "PERF_REG_X86_ES"
    )
    PERF_REG_X86_ES,

    /**
     * {@code PERF_REG_X86_FS = 14}
     */
    @EnumMember(
        value = 14L,
        name = "PERF_REG_X86_FS"
    )
    PERF_REG_X86_FS,

    /**
     * {@code PERF_REG_X86_GS = 15}
     */
    @EnumMember(
        value = 15L,
        name = "PERF_REG_X86_GS"
    )
    PERF_REG_X86_GS,

    /**
     * {@code PERF_REG_X86_R8 = 16}
     */
    @EnumMember(
        value = 16L,
        name = "PERF_REG_X86_R8"
    )
    PERF_REG_X86_R8,

    /**
     * {@code PERF_REG_X86_R9 = 17}
     */
    @EnumMember(
        value = 17L,
        name = "PERF_REG_X86_R9"
    )
    PERF_REG_X86_R9,

    /**
     * {@code PERF_REG_X86_R10 = 18}
     */
    @EnumMember(
        value = 18L,
        name = "PERF_REG_X86_R10"
    )
    PERF_REG_X86_R10,

    /**
     * {@code PERF_REG_X86_R11 = 19}
     */
    @EnumMember(
        value = 19L,
        name = "PERF_REG_X86_R11"
    )
    PERF_REG_X86_R11,

    /**
     * {@code PERF_REG_X86_R12 = 20}
     */
    @EnumMember(
        value = 20L,
        name = "PERF_REG_X86_R12"
    )
    PERF_REG_X86_R12,

    /**
     * {@code PERF_REG_X86_R13 = 21}
     */
    @EnumMember(
        value = 21L,
        name = "PERF_REG_X86_R13"
    )
    PERF_REG_X86_R13,

    /**
     * {@code PERF_REG_X86_R14 = 22}
     */
    @EnumMember(
        value = 22L,
        name = "PERF_REG_X86_R14"
    )
    PERF_REG_X86_R14,

    /**
     * {@code PERF_REG_X86_R15 = 23}
     */
    @EnumMember(
        value = 23L,
        name = "PERF_REG_X86_R15"
    )
    PERF_REG_X86_R15,

    /**
     * {@code PERF_REG_X86_32_MAX = 16}
     */
    @EnumMember(
        value = 16L,
        name = "PERF_REG_X86_32_MAX"
    )
    PERF_REG_X86_32_MAX,

    /**
     * {@code PERF_REG_X86_64_MAX = 24}
     */
    @EnumMember(
        value = 24L,
        name = "PERF_REG_X86_64_MAX"
    )
    PERF_REG_X86_64_MAX,

    /**
     * {@code PERF_REG_X86_XMM0 = 32}
     */
    @EnumMember(
        value = 32L,
        name = "PERF_REG_X86_XMM0"
    )
    PERF_REG_X86_XMM0,

    /**
     * {@code PERF_REG_X86_XMM1 = 34}
     */
    @EnumMember(
        value = 34L,
        name = "PERF_REG_X86_XMM1"
    )
    PERF_REG_X86_XMM1,

    /**
     * {@code PERF_REG_X86_XMM2 = 36}
     */
    @EnumMember(
        value = 36L,
        name = "PERF_REG_X86_XMM2"
    )
    PERF_REG_X86_XMM2,

    /**
     * {@code PERF_REG_X86_XMM3 = 38}
     */
    @EnumMember(
        value = 38L,
        name = "PERF_REG_X86_XMM3"
    )
    PERF_REG_X86_XMM3,

    /**
     * {@code PERF_REG_X86_XMM4 = 40}
     */
    @EnumMember(
        value = 40L,
        name = "PERF_REG_X86_XMM4"
    )
    PERF_REG_X86_XMM4,

    /**
     * {@code PERF_REG_X86_XMM5 = 42}
     */
    @EnumMember(
        value = 42L,
        name = "PERF_REG_X86_XMM5"
    )
    PERF_REG_X86_XMM5,

    /**
     * {@code PERF_REG_X86_XMM6 = 44}
     */
    @EnumMember(
        value = 44L,
        name = "PERF_REG_X86_XMM6"
    )
    PERF_REG_X86_XMM6,

    /**
     * {@code PERF_REG_X86_XMM7 = 46}
     */
    @EnumMember(
        value = 46L,
        name = "PERF_REG_X86_XMM7"
    )
    PERF_REG_X86_XMM7,

    /**
     * {@code PERF_REG_X86_XMM8 = 48}
     */
    @EnumMember(
        value = 48L,
        name = "PERF_REG_X86_XMM8"
    )
    PERF_REG_X86_XMM8,

    /**
     * {@code PERF_REG_X86_XMM9 = 50}
     */
    @EnumMember(
        value = 50L,
        name = "PERF_REG_X86_XMM9"
    )
    PERF_REG_X86_XMM9,

    /**
     * {@code PERF_REG_X86_XMM10 = 52}
     */
    @EnumMember(
        value = 52L,
        name = "PERF_REG_X86_XMM10"
    )
    PERF_REG_X86_XMM10,

    /**
     * {@code PERF_REG_X86_XMM11 = 54}
     */
    @EnumMember(
        value = 54L,
        name = "PERF_REG_X86_XMM11"
    )
    PERF_REG_X86_XMM11,

    /**
     * {@code PERF_REG_X86_XMM12 = 56}
     */
    @EnumMember(
        value = 56L,
        name = "PERF_REG_X86_XMM12"
    )
    PERF_REG_X86_XMM12,

    /**
     * {@code PERF_REG_X86_XMM13 = 58}
     */
    @EnumMember(
        value = 58L,
        name = "PERF_REG_X86_XMM13"
    )
    PERF_REG_X86_XMM13,

    /**
     * {@code PERF_REG_X86_XMM14 = 60}
     */
    @EnumMember(
        value = 60L,
        name = "PERF_REG_X86_XMM14"
    )
    PERF_REG_X86_XMM14,

    /**
     * {@code PERF_REG_X86_XMM15 = 62}
     */
    @EnumMember(
        value = 62L,
        name = "PERF_REG_X86_XMM15"
    )
    PERF_REG_X86_XMM15,

    /**
     * {@code PERF_REG_X86_XMM_MAX = 64}
     */
    @EnumMember(
        value = 64L,
        name = "PERF_REG_X86_XMM_MAX"
    )
    PERF_REG_X86_XMM_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_callchain_entry_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_callchain_entry_ctx extends Struct {
    public Ptr<perf_callchain_entry> entry;

    public @Unsigned int max_stack;

    public @Unsigned int nr;

    public short contexts;

    public boolean contexts_maxed;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_pmu_events_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_pmu_events_attr extends Struct {
    public device_attribute attr;

    public @Unsigned long id;

    public String event_str;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_pmu_events_ht_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_pmu_events_ht_attr extends Struct {
    public device_attribute attr;

    public @Unsigned long id;

    public String event_str_ht;

    public String event_str_noht;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_pmu_events_hybrid_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_pmu_events_hybrid_attr extends Struct {
    public device_attribute attr;

    public @Unsigned long id;

    public String event_str;

    public @Unsigned long pmu_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union perf_capabilities"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_capabilities extends Union {
    public anon_member_of_perf_capabilities anon0;

    public @Unsigned long capabilities;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_sched"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_sched extends Struct {
    public int max_weight;

    public int max_events;

    public int max_gp;

    public int saved_states;

    public Ptr<Ptr<event_constraint>> constraints;

    public sched_state state;

    public sched_state @Size(2) [] saved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_msr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_msr extends Struct {
    public @Unsigned long msr;

    public Ptr<attribute_group> grp;

    public Ptr<?> test;

    public boolean no_check;

    public @Unsigned long mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_event_task_context"
  )
  public enum perf_event_task_context implements Enum<perf_event_task_context>, TypedEnum<perf_event_task_context, java.lang.Integer> {
    /**
     * {@code perf_invalid_context = -1}
     */
    @EnumMember(
        value = -1L,
        name = "perf_invalid_context"
    )
    perf_invalid_context,

    /**
     * {@code perf_hw_context = 0}
     */
    @EnumMember(
        value = 0L,
        name = "perf_hw_context"
    )
    perf_hw_context,

    /**
     * {@code perf_sw_context = 1}
     */
    @EnumMember(
        value = 1L,
        name = "perf_sw_context"
    )
    perf_sw_context,

    /**
     * {@code perf_nr_task_contexts = 2}
     */
    @EnumMember(
        value = 2L,
        name = "perf_nr_task_contexts"
    )
    perf_nr_task_contexts
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_ibs_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_ibs_data extends Struct {
    public @Unsigned int size;

    @InlineUnion(4857)
    public @Unsigned int @Size(0) [] data;

    @InlineUnion(4857)
    public @Unsigned int caps;

    public @Unsigned long @Size(8) [] regs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_ibs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_ibs extends Struct {
    public pmu pmu;

    public @Unsigned int msr;

    public @Unsigned long config_mask;

    public @Unsigned long cnt_mask;

    public @Unsigned long enable_mask;

    public @Unsigned long valid_mask;

    public @Unsigned short min_period;

    public @Unsigned long max_period;

    public @Unsigned long @Size(1) [] offset_mask;

    public int offset_max;

    public @Unsigned int fetch_count_reset_broken;

    public @Unsigned int fetch_ignore_if_zero_rip;

    public Ptr<cpu_perf_ibs> pcpu;

    public Ptr<?> get_count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_amd_iommu"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_amd_iommu extends Struct {
    public list_head list;

    public pmu pmu;

    public Ptr<amd_iommu> iommu;

    public char @Size(24) [] name;

    public char max_banks;

    public char max_counters;

    public @Unsigned long cntr_assign_mask;

    public @OriginalName("raw_spinlock_t") raw_spinlock lock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_msr_id"
  )
  public enum perf_msr_id implements Enum<perf_msr_id>, TypedEnum<perf_msr_id, java.lang. @Unsigned Integer> {
    /**
     * {@code PERF_MSR_TSC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PERF_MSR_TSC"
    )
    PERF_MSR_TSC,

    /**
     * {@code PERF_MSR_APERF = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PERF_MSR_APERF"
    )
    PERF_MSR_APERF,

    /**
     * {@code PERF_MSR_MPERF = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PERF_MSR_MPERF"
    )
    PERF_MSR_MPERF,

    /**
     * {@code PERF_MSR_PPERF = 3}
     */
    @EnumMember(
        value = 3L,
        name = "PERF_MSR_PPERF"
    )
    PERF_MSR_PPERF,

    /**
     * {@code PERF_MSR_SMI = 4}
     */
    @EnumMember(
        value = 4L,
        name = "PERF_MSR_SMI"
    )
    PERF_MSR_SMI,

    /**
     * {@code PERF_MSR_PTSC = 5}
     */
    @EnumMember(
        value = 5L,
        name = "PERF_MSR_PTSC"
    )
    PERF_MSR_PTSC,

    /**
     * {@code PERF_MSR_IRPERF = 6}
     */
    @EnumMember(
        value = 6L,
        name = "PERF_MSR_IRPERF"
    )
    PERF_MSR_IRPERF,

    /**
     * {@code PERF_MSR_THERM = 7}
     */
    @EnumMember(
        value = 7L,
        name = "PERF_MSR_THERM"
    )
    PERF_MSR_THERM,

    /**
     * {@code PERF_MSR_EVENT_MAX = 8}
     */
    @EnumMember(
        value = 8L,
        name = "PERF_MSR_EVENT_MAX"
    )
    PERF_MSR_EVENT_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_pmu_format_hybrid_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_pmu_format_hybrid_attr extends Struct {
    public device_attribute attr;

    public @Unsigned long pmu_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_event_header"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_event_header extends Struct {
    public @Unsigned int type;

    public @Unsigned short misc;

    public @Unsigned short size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_addr_filter_action_t"
  )
  public enum perf_addr_filter_action_t implements Enum<perf_addr_filter_action_t>, TypedEnum<perf_addr_filter_action_t, java.lang. @Unsigned Integer> {
    /**
     * {@code PERF_ADDR_FILTER_ACTION_STOP = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PERF_ADDR_FILTER_ACTION_STOP"
    )
    PERF_ADDR_FILTER_ACTION_STOP,

    /**
     * {@code PERF_ADDR_FILTER_ACTION_START = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PERF_ADDR_FILTER_ACTION_START"
    )
    PERF_ADDR_FILTER_ACTION_START,

    /**
     * {@code PERF_ADDR_FILTER_ACTION_FILTER = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PERF_ADDR_FILTER_ACTION_FILTER"
    )
    PERF_ADDR_FILTER_ACTION_FILTER
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_addr_filter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_addr_filter extends Struct {
    public list_head entry;

    public path path;

    public @Unsigned long offset;

    public @Unsigned long size;

    public perf_addr_filter_action_t action;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_snb_uncore_imc_freerunning_types"
  )
  public enum perf_snb_uncore_imc_freerunning_types implements Enum<perf_snb_uncore_imc_freerunning_types>, TypedEnum<perf_snb_uncore_imc_freerunning_types, java.lang. @Unsigned Integer> {
    /**
     * {@code SNB_PCI_UNCORE_IMC_DATA_READS = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SNB_PCI_UNCORE_IMC_DATA_READS"
    )
    SNB_PCI_UNCORE_IMC_DATA_READS,

    /**
     * {@code SNB_PCI_UNCORE_IMC_DATA_WRITES = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SNB_PCI_UNCORE_IMC_DATA_WRITES"
    )
    SNB_PCI_UNCORE_IMC_DATA_WRITES,

    /**
     * {@code SNB_PCI_UNCORE_IMC_GT_REQUESTS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SNB_PCI_UNCORE_IMC_GT_REQUESTS"
    )
    SNB_PCI_UNCORE_IMC_GT_REQUESTS,

    /**
     * {@code SNB_PCI_UNCORE_IMC_IA_REQUESTS = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SNB_PCI_UNCORE_IMC_IA_REQUESTS"
    )
    SNB_PCI_UNCORE_IMC_IA_REQUESTS,

    /**
     * {@code SNB_PCI_UNCORE_IMC_IO_REQUESTS = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SNB_PCI_UNCORE_IMC_IO_REQUESTS"
    )
    SNB_PCI_UNCORE_IMC_IO_REQUESTS,

    /**
     * {@code SNB_PCI_UNCORE_IMC_FREERUNNING_TYPE_MAX = 5}
     */
    @EnumMember(
        value = 5L,
        name = "SNB_PCI_UNCORE_IMC_FREERUNNING_TYPE_MAX"
    )
    SNB_PCI_UNCORE_IMC_FREERUNNING_TYPE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_tgl_uncore_imc_freerunning_types"
  )
  public enum perf_tgl_uncore_imc_freerunning_types implements Enum<perf_tgl_uncore_imc_freerunning_types>, TypedEnum<perf_tgl_uncore_imc_freerunning_types, java.lang. @Unsigned Integer> {
    /**
     * {@code TGL_MMIO_UNCORE_IMC_DATA_TOTAL = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TGL_MMIO_UNCORE_IMC_DATA_TOTAL"
    )
    TGL_MMIO_UNCORE_IMC_DATA_TOTAL,

    /**
     * {@code TGL_MMIO_UNCORE_IMC_DATA_READ = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TGL_MMIO_UNCORE_IMC_DATA_READ"
    )
    TGL_MMIO_UNCORE_IMC_DATA_READ,

    /**
     * {@code TGL_MMIO_UNCORE_IMC_DATA_WRITE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TGL_MMIO_UNCORE_IMC_DATA_WRITE"
    )
    TGL_MMIO_UNCORE_IMC_DATA_WRITE,

    /**
     * {@code TGL_MMIO_UNCORE_IMC_FREERUNNING_TYPE_MAX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TGL_MMIO_UNCORE_IMC_FREERUNNING_TYPE_MAX"
    )
    TGL_MMIO_UNCORE_IMC_FREERUNNING_TYPE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_adl_uncore_imc_freerunning_types"
  )
  public enum perf_adl_uncore_imc_freerunning_types implements Enum<perf_adl_uncore_imc_freerunning_types>, TypedEnum<perf_adl_uncore_imc_freerunning_types, java.lang. @Unsigned Integer> {
    /**
     * {@code ADL_MMIO_UNCORE_IMC_DATA_TOTAL = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ADL_MMIO_UNCORE_IMC_DATA_TOTAL"
    )
    ADL_MMIO_UNCORE_IMC_DATA_TOTAL,

    /**
     * {@code ADL_MMIO_UNCORE_IMC_DATA_READ = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ADL_MMIO_UNCORE_IMC_DATA_READ"
    )
    ADL_MMIO_UNCORE_IMC_DATA_READ,

    /**
     * {@code ADL_MMIO_UNCORE_IMC_DATA_WRITE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ADL_MMIO_UNCORE_IMC_DATA_WRITE"
    )
    ADL_MMIO_UNCORE_IMC_DATA_WRITE,

    /**
     * {@code ADL_MMIO_UNCORE_IMC_FREERUNNING_TYPE_MAX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ADL_MMIO_UNCORE_IMC_FREERUNNING_TYPE_MAX"
    )
    ADL_MMIO_UNCORE_IMC_FREERUNNING_TYPE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_uncore_iio_freerunning_type_id"
  )
  public enum perf_uncore_iio_freerunning_type_id implements Enum<perf_uncore_iio_freerunning_type_id>, TypedEnum<perf_uncore_iio_freerunning_type_id, java.lang. @Unsigned Integer> {
    /**
     * {@code SKX_IIO_MSR_IOCLK = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SKX_IIO_MSR_IOCLK"
    )
    SKX_IIO_MSR_IOCLK,

    /**
     * {@code SKX_IIO_MSR_BW = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SKX_IIO_MSR_BW"
    )
    SKX_IIO_MSR_BW,

    /**
     * {@code SKX_IIO_MSR_UTIL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SKX_IIO_MSR_UTIL"
    )
    SKX_IIO_MSR_UTIL,

    /**
     * {@code SKX_IIO_FREERUNNING_TYPE_MAX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SKX_IIO_FREERUNNING_TYPE_MAX"
    )
    SKX_IIO_FREERUNNING_TYPE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_uncore_snr_iio_freerunning_type_id"
  )
  public enum perf_uncore_snr_iio_freerunning_type_id implements Enum<perf_uncore_snr_iio_freerunning_type_id>, TypedEnum<perf_uncore_snr_iio_freerunning_type_id, java.lang. @Unsigned Integer> {
    /**
     * {@code SNR_IIO_MSR_IOCLK = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SNR_IIO_MSR_IOCLK"
    )
    SNR_IIO_MSR_IOCLK,

    /**
     * {@code SNR_IIO_MSR_BW_IN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SNR_IIO_MSR_BW_IN"
    )
    SNR_IIO_MSR_BW_IN,

    /**
     * {@code SNR_IIO_FREERUNNING_TYPE_MAX = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SNR_IIO_FREERUNNING_TYPE_MAX"
    )
    SNR_IIO_FREERUNNING_TYPE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_uncore_snr_imc_freerunning_type_id"
  )
  public enum perf_uncore_snr_imc_freerunning_type_id implements Enum<perf_uncore_snr_imc_freerunning_type_id>, TypedEnum<perf_uncore_snr_imc_freerunning_type_id, java.lang. @Unsigned Integer> {
    /**
     * {@code SNR_IMC_DCLK = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SNR_IMC_DCLK"
    )
    SNR_IMC_DCLK,

    /**
     * {@code SNR_IMC_DDR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SNR_IMC_DDR"
    )
    SNR_IMC_DDR,

    /**
     * {@code SNR_IMC_FREERUNNING_TYPE_MAX = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SNR_IMC_FREERUNNING_TYPE_MAX"
    )
    SNR_IMC_FREERUNNING_TYPE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_uncore_icx_iio_freerunning_type_id"
  )
  public enum perf_uncore_icx_iio_freerunning_type_id implements Enum<perf_uncore_icx_iio_freerunning_type_id>, TypedEnum<perf_uncore_icx_iio_freerunning_type_id, java.lang. @Unsigned Integer> {
    /**
     * {@code ICX_IIO_MSR_IOCLK = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ICX_IIO_MSR_IOCLK"
    )
    ICX_IIO_MSR_IOCLK,

    /**
     * {@code ICX_IIO_MSR_BW_IN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ICX_IIO_MSR_BW_IN"
    )
    ICX_IIO_MSR_BW_IN,

    /**
     * {@code ICX_IIO_FREERUNNING_TYPE_MAX = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ICX_IIO_FREERUNNING_TYPE_MAX"
    )
    ICX_IIO_FREERUNNING_TYPE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_uncore_icx_imc_freerunning_type_id"
  )
  public enum perf_uncore_icx_imc_freerunning_type_id implements Enum<perf_uncore_icx_imc_freerunning_type_id>, TypedEnum<perf_uncore_icx_imc_freerunning_type_id, java.lang. @Unsigned Integer> {
    /**
     * {@code ICX_IMC_DCLK = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ICX_IMC_DCLK"
    )
    ICX_IMC_DCLK,

    /**
     * {@code ICX_IMC_DDR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ICX_IMC_DDR"
    )
    ICX_IMC_DDR,

    /**
     * {@code ICX_IMC_DDRT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ICX_IMC_DDRT"
    )
    ICX_IMC_DDRT,

    /**
     * {@code ICX_IMC_FREERUNNING_TYPE_MAX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ICX_IMC_FREERUNNING_TYPE_MAX"
    )
    ICX_IMC_FREERUNNING_TYPE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_uncore_spr_iio_freerunning_type_id"
  )
  public enum perf_uncore_spr_iio_freerunning_type_id implements Enum<perf_uncore_spr_iio_freerunning_type_id>, TypedEnum<perf_uncore_spr_iio_freerunning_type_id, java.lang. @Unsigned Integer> {
    /**
     * {@code SPR_IIO_MSR_IOCLK = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SPR_IIO_MSR_IOCLK"
    )
    SPR_IIO_MSR_IOCLK,

    /**
     * {@code SPR_IIO_MSR_BW_IN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SPR_IIO_MSR_BW_IN"
    )
    SPR_IIO_MSR_BW_IN,

    /**
     * {@code SPR_IIO_MSR_BW_OUT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SPR_IIO_MSR_BW_OUT"
    )
    SPR_IIO_MSR_BW_OUT,

    /**
     * {@code SPR_IIO_FREERUNNING_TYPE_MAX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SPR_IIO_FREERUNNING_TYPE_MAX"
    )
    SPR_IIO_FREERUNNING_TYPE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_uncore_spr_imc_freerunning_type_id"
  )
  public enum perf_uncore_spr_imc_freerunning_type_id implements Enum<perf_uncore_spr_imc_freerunning_type_id>, TypedEnum<perf_uncore_spr_imc_freerunning_type_id, java.lang. @Unsigned Integer> {
    /**
     * {@code SPR_IMC_DCLK = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SPR_IMC_DCLK"
    )
    SPR_IMC_DCLK,

    /**
     * {@code SPR_IMC_PQ_CYCLES = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SPR_IMC_PQ_CYCLES"
    )
    SPR_IMC_PQ_CYCLES,

    /**
     * {@code SPR_IMC_FREERUNNING_TYPE_MAX = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SPR_IMC_FREERUNNING_TYPE_MAX"
    )
    SPR_IMC_FREERUNNING_TYPE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_guest_info_callbacks"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_guest_info_callbacks extends Struct {
    public Ptr<?> state;

    public Ptr<?> get_ip;

    public Ptr<?> handle_intel_pt_intr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int _data; unsigned int _type; unsigned int _flags; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class _perf_of_anon_member_of__sigfault_of__sifields_of_compat_siginfo_and__sifields_of_compat_siginfo_t extends Struct {
    public @Unsigned @OriginalName("compat_ulong_t") int _data;

    public @Unsigned int _type;

    public @Unsigned int _flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_sample_regs_abi"
  )
  public enum perf_sample_regs_abi implements Enum<perf_sample_regs_abi>, TypedEnum<perf_sample_regs_abi, java.lang. @Unsigned Integer> {
    /**
     * {@code PERF_SAMPLE_REGS_ABI_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PERF_SAMPLE_REGS_ABI_NONE"
    )
    PERF_SAMPLE_REGS_ABI_NONE,

    /**
     * {@code PERF_SAMPLE_REGS_ABI_32 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PERF_SAMPLE_REGS_ABI_32"
    )
    PERF_SAMPLE_REGS_ABI_32,

    /**
     * {@code PERF_SAMPLE_REGS_ABI_64 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PERF_SAMPLE_REGS_ABI_64"
    )
    PERF_SAMPLE_REGS_ABI_64
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_domain"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_domain extends Struct {
    public Ptr<em_perf_domain> em_pd;

    public Ptr<perf_domain> next;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_record_ksymbol_type"
  )
  public enum perf_record_ksymbol_type implements Enum<perf_record_ksymbol_type>, TypedEnum<perf_record_ksymbol_type, java.lang. @Unsigned Integer> {
    /**
     * {@code PERF_RECORD_KSYMBOL_TYPE_UNKNOWN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PERF_RECORD_KSYMBOL_TYPE_UNKNOWN"
    )
    PERF_RECORD_KSYMBOL_TYPE_UNKNOWN,

    /**
     * {@code PERF_RECORD_KSYMBOL_TYPE_BPF = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PERF_RECORD_KSYMBOL_TYPE_BPF"
    )
    PERF_RECORD_KSYMBOL_TYPE_BPF,

    /**
     * {@code PERF_RECORD_KSYMBOL_TYPE_OOL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PERF_RECORD_KSYMBOL_TYPE_OOL"
    )
    PERF_RECORD_KSYMBOL_TYPE_OOL,

    /**
     * {@code PERF_RECORD_KSYMBOL_TYPE_MAX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "PERF_RECORD_KSYMBOL_TYPE_MAX"
    )
    PERF_RECORD_KSYMBOL_TYPE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_event_query_bpf"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_event_query_bpf extends Struct {
    public @Unsigned int ids_len;

    public @Unsigned int prog_cnt;

    public @Unsigned int @Size(0) [] ids;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_bpf_event_type"
  )
  public enum perf_bpf_event_type implements Enum<perf_bpf_event_type>, TypedEnum<perf_bpf_event_type, java.lang. @Unsigned Integer> {
    /**
     * {@code PERF_BPF_EVENT_UNKNOWN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PERF_BPF_EVENT_UNKNOWN"
    )
    PERF_BPF_EVENT_UNKNOWN,

    /**
     * {@code PERF_BPF_EVENT_PROG_LOAD = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PERF_BPF_EVENT_PROG_LOAD"
    )
    PERF_BPF_EVENT_PROG_LOAD,

    /**
     * {@code PERF_BPF_EVENT_PROG_UNLOAD = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PERF_BPF_EVENT_PROG_UNLOAD"
    )
    PERF_BPF_EVENT_PROG_UNLOAD,

    /**
     * {@code PERF_BPF_EVENT_MAX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "PERF_BPF_EVENT_MAX"
    )
    PERF_BPF_EVENT_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_callchain_context"
  )
  public enum perf_callchain_context implements Enum<perf_callchain_context>, TypedEnum<perf_callchain_context, java.lang. @Unsigned Long> {
    /**
     * {@code PERF_CONTEXT_HV = -32}
     */
    @EnumMember(
        value = -32L,
        name = "PERF_CONTEXT_HV"
    )
    PERF_CONTEXT_HV,

    /**
     * {@code PERF_CONTEXT_KERNEL = -128}
     */
    @EnumMember(
        value = -128L,
        name = "PERF_CONTEXT_KERNEL"
    )
    PERF_CONTEXT_KERNEL,

    /**
     * {@code PERF_CONTEXT_USER = -512}
     */
    @EnumMember(
        value = -512L,
        name = "PERF_CONTEXT_USER"
    )
    PERF_CONTEXT_USER,

    /**
     * {@code PERF_CONTEXT_GUEST = -2048}
     */
    @EnumMember(
        value = -2048L,
        name = "PERF_CONTEXT_GUEST"
    )
    PERF_CONTEXT_GUEST,

    /**
     * {@code PERF_CONTEXT_GUEST_KERNEL = -2176}
     */
    @EnumMember(
        value = -2176L,
        name = "PERF_CONTEXT_GUEST_KERNEL"
    )
    PERF_CONTEXT_GUEST_KERNEL,

    /**
     * {@code PERF_CONTEXT_GUEST_USER = -2560}
     */
    @EnumMember(
        value = -2560L,
        name = "PERF_CONTEXT_GUEST_USER"
    )
    PERF_CONTEXT_GUEST_USER,

    /**
     * {@code PERF_CONTEXT_MAX = -4095}
     */
    @EnumMember(
        value = -4095L,
        name = "PERF_CONTEXT_MAX"
    )
    PERF_CONTEXT_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_event_read_format"
  )
  public enum perf_event_read_format implements Enum<perf_event_read_format>, TypedEnum<perf_event_read_format, java.lang. @Unsigned Integer> {
    /**
     * {@code PERF_FORMAT_TOTAL_TIME_ENABLED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PERF_FORMAT_TOTAL_TIME_ENABLED"
    )
    PERF_FORMAT_TOTAL_TIME_ENABLED,

    /**
     * {@code PERF_FORMAT_TOTAL_TIME_RUNNING = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PERF_FORMAT_TOTAL_TIME_RUNNING"
    )
    PERF_FORMAT_TOTAL_TIME_RUNNING,

    /**
     * {@code PERF_FORMAT_ID = 4}
     */
    @EnumMember(
        value = 4L,
        name = "PERF_FORMAT_ID"
    )
    PERF_FORMAT_ID,

    /**
     * {@code PERF_FORMAT_GROUP = 8}
     */
    @EnumMember(
        value = 8L,
        name = "PERF_FORMAT_GROUP"
    )
    PERF_FORMAT_GROUP,

    /**
     * {@code PERF_FORMAT_LOST = 16}
     */
    @EnumMember(
        value = 16L,
        name = "PERF_FORMAT_LOST"
    )
    PERF_FORMAT_LOST,

    /**
     * {@code PERF_FORMAT_MAX = 32}
     */
    @EnumMember(
        value = 32L,
        name = "PERF_FORMAT_MAX"
    )
    PERF_FORMAT_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_event_ioc_flags"
  )
  public enum perf_event_ioc_flags implements Enum<perf_event_ioc_flags>, TypedEnum<perf_event_ioc_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code PERF_IOC_FLAG_GROUP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PERF_IOC_FLAG_GROUP"
    )
    PERF_IOC_FLAG_GROUP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_ns_link_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_ns_link_info extends Struct {
    public @Unsigned long dev;

    public @Unsigned long ino;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_event_type"
  )
  public enum perf_event_type implements Enum<perf_event_type>, TypedEnum<perf_event_type, java.lang. @Unsigned Integer> {
    /**
     * {@code PERF_RECORD_MMAP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PERF_RECORD_MMAP"
    )
    PERF_RECORD_MMAP,

    /**
     * {@code PERF_RECORD_LOST = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PERF_RECORD_LOST"
    )
    PERF_RECORD_LOST,

    /**
     * {@code PERF_RECORD_COMM = 3}
     */
    @EnumMember(
        value = 3L,
        name = "PERF_RECORD_COMM"
    )
    PERF_RECORD_COMM,

    /**
     * {@code PERF_RECORD_EXIT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "PERF_RECORD_EXIT"
    )
    PERF_RECORD_EXIT,

    /**
     * {@code PERF_RECORD_THROTTLE = 5}
     */
    @EnumMember(
        value = 5L,
        name = "PERF_RECORD_THROTTLE"
    )
    PERF_RECORD_THROTTLE,

    /**
     * {@code PERF_RECORD_UNTHROTTLE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "PERF_RECORD_UNTHROTTLE"
    )
    PERF_RECORD_UNTHROTTLE,

    /**
     * {@code PERF_RECORD_FORK = 7}
     */
    @EnumMember(
        value = 7L,
        name = "PERF_RECORD_FORK"
    )
    PERF_RECORD_FORK,

    /**
     * {@code PERF_RECORD_READ = 8}
     */
    @EnumMember(
        value = 8L,
        name = "PERF_RECORD_READ"
    )
    PERF_RECORD_READ,

    /**
     * {@code PERF_RECORD_SAMPLE = 9}
     */
    @EnumMember(
        value = 9L,
        name = "PERF_RECORD_SAMPLE"
    )
    PERF_RECORD_SAMPLE,

    /**
     * {@code PERF_RECORD_MMAP2 = 10}
     */
    @EnumMember(
        value = 10L,
        name = "PERF_RECORD_MMAP2"
    )
    PERF_RECORD_MMAP2,

    /**
     * {@code PERF_RECORD_AUX = 11}
     */
    @EnumMember(
        value = 11L,
        name = "PERF_RECORD_AUX"
    )
    PERF_RECORD_AUX,

    /**
     * {@code PERF_RECORD_ITRACE_START = 12}
     */
    @EnumMember(
        value = 12L,
        name = "PERF_RECORD_ITRACE_START"
    )
    PERF_RECORD_ITRACE_START,

    /**
     * {@code PERF_RECORD_LOST_SAMPLES = 13}
     */
    @EnumMember(
        value = 13L,
        name = "PERF_RECORD_LOST_SAMPLES"
    )
    PERF_RECORD_LOST_SAMPLES,

    /**
     * {@code PERF_RECORD_SWITCH = 14}
     */
    @EnumMember(
        value = 14L,
        name = "PERF_RECORD_SWITCH"
    )
    PERF_RECORD_SWITCH,

    /**
     * {@code PERF_RECORD_SWITCH_CPU_WIDE = 15}
     */
    @EnumMember(
        value = 15L,
        name = "PERF_RECORD_SWITCH_CPU_WIDE"
    )
    PERF_RECORD_SWITCH_CPU_WIDE,

    /**
     * {@code PERF_RECORD_NAMESPACES = 16}
     */
    @EnumMember(
        value = 16L,
        name = "PERF_RECORD_NAMESPACES"
    )
    PERF_RECORD_NAMESPACES,

    /**
     * {@code PERF_RECORD_KSYMBOL = 17}
     */
    @EnumMember(
        value = 17L,
        name = "PERF_RECORD_KSYMBOL"
    )
    PERF_RECORD_KSYMBOL,

    /**
     * {@code PERF_RECORD_BPF_EVENT = 18}
     */
    @EnumMember(
        value = 18L,
        name = "PERF_RECORD_BPF_EVENT"
    )
    PERF_RECORD_BPF_EVENT,

    /**
     * {@code PERF_RECORD_CGROUP = 19}
     */
    @EnumMember(
        value = 19L,
        name = "PERF_RECORD_CGROUP"
    )
    PERF_RECORD_CGROUP,

    /**
     * {@code PERF_RECORD_TEXT_POKE = 20}
     */
    @EnumMember(
        value = 20L,
        name = "PERF_RECORD_TEXT_POKE"
    )
    PERF_RECORD_TEXT_POKE,

    /**
     * {@code PERF_RECORD_AUX_OUTPUT_HW_ID = 21}
     */
    @EnumMember(
        value = 21L,
        name = "PERF_RECORD_AUX_OUTPUT_HW_ID"
    )
    PERF_RECORD_AUX_OUTPUT_HW_ID,

    /**
     * {@code PERF_RECORD_MAX = 22}
     */
    @EnumMember(
        value = 22L,
        name = "PERF_RECORD_MAX"
    )
    PERF_RECORD_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_pmu_scope"
  )
  public enum perf_pmu_scope implements Enum<perf_pmu_scope>, TypedEnum<perf_pmu_scope, java.lang. @Unsigned Integer> {
    /**
     * {@code PERF_PMU_SCOPE_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PERF_PMU_SCOPE_NONE"
    )
    PERF_PMU_SCOPE_NONE,

    /**
     * {@code PERF_PMU_SCOPE_CORE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PERF_PMU_SCOPE_CORE"
    )
    PERF_PMU_SCOPE_CORE,

    /**
     * {@code PERF_PMU_SCOPE_DIE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PERF_PMU_SCOPE_DIE"
    )
    PERF_PMU_SCOPE_DIE,

    /**
     * {@code PERF_PMU_SCOPE_CLUSTER = 3}
     */
    @EnumMember(
        value = 3L,
        name = "PERF_PMU_SCOPE_CLUSTER"
    )
    PERF_PMU_SCOPE_CLUSTER,

    /**
     * {@code PERF_PMU_SCOPE_PKG = 4}
     */
    @EnumMember(
        value = 4L,
        name = "PERF_PMU_SCOPE_PKG"
    )
    PERF_PMU_SCOPE_PKG,

    /**
     * {@code PERF_PMU_SCOPE_SYS_WIDE = 5}
     */
    @EnumMember(
        value = 5L,
        name = "PERF_PMU_SCOPE_SYS_WIDE"
    )
    PERF_PMU_SCOPE_SYS_WIDE,

    /**
     * {@code PERF_PMU_MAX_SCOPE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "PERF_PMU_MAX_SCOPE"
    )
    PERF_PMU_MAX_SCOPE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_buffer"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_buffer extends Struct {
    public @OriginalName("refcount_t") refcount_struct refcount;

    public callback_head callback_head;

    public int nr_pages;

    public int overwrite;

    public int paused;

    public atomic_t poll;

    public local_t head;

    public @Unsigned int nest;

    public local_t events;

    public local_t wakeup;

    public local_t lost;

    public long watermark;

    public long aux_watermark;

    public @OriginalName("spinlock_t") spinlock event_lock;

    public list_head event_list;

    public atomic_t mmap_count;

    public @Unsigned long mmap_locked;

    public Ptr<user_struct> mmap_user;

    public mutex aux_mutex;

    public long aux_head;

    public @Unsigned int aux_nest;

    public long aux_wakeup;

    public @Unsigned long aux_pgoff;

    public int aux_nr_pages;

    public int aux_overwrite;

    public atomic_t aux_mmap_count;

    public @Unsigned long aux_mmap_locked;

    public Ptr<?> free_aux;

    public @OriginalName("refcount_t") refcount_struct aux_refcount;

    public int aux_in_sampling;

    public int aux_in_pause_resume;

    public Ptr<Ptr<?>> aux_pages;

    public Ptr<?> aux_priv;

    public Ptr<perf_event_mmap_page> user_page;

    public Ptr<?> @Size(0) [] data_pages;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_cpu_context"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_cpu_context extends Struct {
    public perf_event_context ctx;

    public Ptr<perf_event_context> task_ctx;

    public int online;

    public Ptr<perf_cgroup> cgrp;

    public int heap_size;

    public Ptr<Ptr<perf_event>> heap;

    public Ptr<perf_event> @Size(2) [] heap_default;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_event_min_heap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_event_min_heap extends Struct {
    public @Unsigned long nr;

    public @Unsigned long size;

    public Ptr<Ptr<perf_event>> data;

    public Ptr<perf_event> @Size(0) [] preallocated;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_read_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_read_data extends Struct {
    public Ptr<perf_event> event;

    public boolean group;

    public int ret;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_read_event"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_read_event extends Struct {
    public perf_event_header header;

    public @Unsigned int pid;

    public @Unsigned int tid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_task_event"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_task_event extends Struct {
    public Ptr<task_struct> task;

    public Ptr<perf_event_context> task_ctx;

    public event_id_of_perf_task_event event_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_comm_event"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_comm_event extends Struct {
    public Ptr<task_struct> task;

    public String comm;

    public int comm_size;

    public event_id_of_perf_comm_event event_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_namespaces_event"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_namespaces_event extends Struct {
    public Ptr<task_struct> task;

    public event_id_of_perf_namespaces_event event_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_cgroup_event"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_cgroup_event extends Struct {
    public String path;

    public int path_size;

    public event_id_of_perf_cgroup_event event_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_mmap_event"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_mmap_event extends Struct {
    public Ptr<vm_area_struct> vma;

    public String file_name;

    public int file_size;

    public int maj;

    public int min;

    public @Unsigned long ino;

    public @Unsigned long ino_generation;

    public @Unsigned int prot;

    public @Unsigned int flags;

    public char @Size(20) [] build_id;

    public @Unsigned int build_id_size;

    public event_id_of_perf_mmap_event event_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_switch_event"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_switch_event extends Struct {
    public Ptr<task_struct> task;

    public Ptr<task_struct> next_prev;

    public event_id_of_perf_switch_event event_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_ksymbol_event"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_ksymbol_event extends Struct {
    public String name;

    public int name_len;

    public event_id_of_perf_ksymbol_event event_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_bpf_event"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_bpf_event extends Struct {
    public Ptr<bpf_prog> prog;

    public event_id_of_perf_bpf_event event_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_text_poke_event"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_text_poke_event extends Struct {
    public Ptr<?> old_bytes;

    public Ptr<?> new_bytes;

    public @Unsigned long pad;

    public @Unsigned short old_len;

    public @Unsigned short new_len;

    public event_id_of_perf_text_poke_event event_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum perf_probe_config"
  )
  public enum perf_probe_config implements Enum<perf_probe_config>, TypedEnum<perf_probe_config, java.lang. @Unsigned Integer> {
    /**
     * {@code PERF_PROBE_CONFIG_IS_RETPROBE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PERF_PROBE_CONFIG_IS_RETPROBE"
    )
    PERF_PROBE_CONFIG_IS_RETPROBE,

    /**
     * {@code PERF_UPROBE_REF_CTR_OFFSET_BITS = 32}
     */
    @EnumMember(
        value = 32L,
        name = "PERF_UPROBE_REF_CTR_OFFSET_BITS"
    )
    PERF_UPROBE_REF_CTR_OFFSET_BITS,

    /**
     * {@code PERF_UPROBE_REF_CTR_OFFSET_SHIFT = 32}
     */
    @EnumMember(
        value = 32L,
        name = "PERF_UPROBE_REF_CTR_OFFSET_SHIFT"
    )
    PERF_UPROBE_REF_CTR_OFFSET_SHIFT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_aux_event"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_aux_event extends Struct {
    public perf_event_header header;

    public @Unsigned long hw_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct perf_event_security_struct"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_event_security_struct extends Struct {
    public @Unsigned int sid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union perf_cached"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class perf_cached extends Union {
    public anon_member_of_perf_cached anon0;

    public @Unsigned long val;
  }
}
