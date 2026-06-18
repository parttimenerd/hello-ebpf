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
 * Generated class for BPF runtime types that start with power
 */
@java.lang.SuppressWarnings("unused")
public final class PowerDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __power_supply_am_i_supplied(Ptr<power_supply> epsy, Ptr<?> _data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __power_supply_changed_work(Ptr<power_supply> pst, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __power_supply_get_property(Ptr<power_supply> psy, power_supply_property psp,
      Ptr<power_supply_propval> val, boolean use_extensions) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __power_supply_get_supplier_property(Ptr<power_supply> epsy, Ptr<?> _data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __power_supply_is_supplied_by(Ptr<power_supply> supplier,
      Ptr<power_supply> supply) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __power_supply_is_system_supplied(Ptr<power_supply> psy, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__power_supply_register($arg1, (const struct power_supply_desc*)$arg2, (const struct power_supply_config*)$arg3)")
  public static Ptr<power_supply> __power_supply_register(Ptr<device> parent,
      Ptr<power_supply_desc> desc, Ptr<power_supply_config> cfg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__power_supply_set_property($arg1, $arg2, (const union power_supply_propval*)$arg3, $arg4)")
  public static int __power_supply_set_property(Ptr<power_supply> psy, power_supply_property psp,
      Ptr<power_supply_propval> val, boolean use_extensions) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int power_allocator_bind(Ptr<thermal_zone_device> tz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void power_allocator_manage(Ptr<thermal_zone_device> tz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void power_allocator_unbind(Ptr<thermal_zone_device> tz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void power_allocator_update_tz(Ptr<thermal_zone_device> tz,
      thermal_notify_event reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void power_allocator_update_weight(Ptr<power_allocator_params> params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long power_budget_milliwatt_show(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long power_read_file(Ptr<pci_slot> pci_slot, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long power_requested_milliwatt_show(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long power_state_show(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int power_supply_add_hwmon_sysfs(Ptr<power_supply> psy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int power_supply_am_i_supplied(Ptr<power_supply> psy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("umode_t") short power_supply_attr_is_visible(
      Ptr<kobject> kobj, Ptr<attribute> attr, int attrno) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int power_supply_batinfo_ocv2cap(Ptr<power_supply_battery_info> info, int ocv,
      int temp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean power_supply_battery_bti_in_range(Ptr<power_supply_battery_info> info,
      int resistance) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int power_supply_battery_info_get_prop(Ptr<power_supply_battery_info> info,
      power_supply_property psp, Ptr<power_supply_propval> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean power_supply_battery_info_has_prop(Ptr<power_supply_battery_info> info,
      power_supply_property psp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void power_supply_changed(Ptr<power_supply> psy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void power_supply_changed_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_charge_behaviour_parse($arg1, (const u8*)$arg2)")
  public static int power_supply_charge_behaviour_parse(@Unsigned int available_behaviours,
      String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long power_supply_charge_behaviour_show(Ptr<device> dev,
      @Unsigned int available_behaviours, power_supply_charge_behaviour current_behaviour,
      String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_charge_types_parse($arg1, (const u8*)$arg2)")
  public static int power_supply_charge_types_parse(@Unsigned int available_types, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long power_supply_charge_types_show(Ptr<device> dev,
      @Unsigned int available_types, power_supply_charge_type current_type, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void power_supply_class_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int power_supply_class_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int power_supply_create_triggers(Ptr<power_supply> psy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void power_supply_deferred_register_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void power_supply_dev_release(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_escape_spaces((const u8*)$arg1, $arg2, $arg3)")
  public static void power_supply_escape_spaces(String str, String buf, @Unsigned long bufsize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_ext_has_property((const struct power_supply_ext*)$arg1, $arg2)")
  public static boolean power_supply_ext_has_property(Ptr<power_supply_ext> psy_ext,
      power_supply_property psp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void power_supply_external_power_changed(Ptr<power_supply> psy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct power_supply_battery_ocv_table*)power_supply_find_ocv2cap_table($arg1, $arg2, $arg3))")
  public static Ptr<power_supply_battery_ocv_table> power_supply_find_ocv2cap_table(
      Ptr<power_supply_battery_info> info, int temp, Ptr<java.lang.Integer> table_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_for_each_psy($arg1, (int (*)(struct power_supply*, void*))$arg2)")
  public static int power_supply_for_each_psy(Ptr<?> data, Ptr<?> fn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long power_supply_format_property(Ptr<device> dev,
      boolean uevent, Ptr<device_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int power_supply_get_battery_info(Ptr<power_supply> psy,
      Ptr<Ptr<power_supply_battery_info>> info_out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_get_by_name((const u8*)$arg1)")
  public static Ptr<power_supply> power_supply_get_by_name(String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_get_by_reference($arg1, (const u8*)$arg2)")
  public static Ptr<power_supply> power_supply_get_by_reference(Ptr<fwnode_handle> fwnode,
      String property) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> power_supply_get_drvdata(Ptr<power_supply> psy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct power_supply_maintenance_charge_table*)power_supply_get_maintenance_charging_setting($arg1, $arg2))")
  public static Ptr<power_supply_maintenance_charge_table> power_supply_get_maintenance_charging_setting(
      Ptr<power_supply_battery_info> info, int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int power_supply_get_property(Ptr<power_supply> psy, power_supply_property psp,
      Ptr<power_supply_propval> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int power_supply_get_property_direct(Ptr<power_supply> psy,
      power_supply_property psp, Ptr<power_supply_propval> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int power_supply_get_property_from_supplier(Ptr<power_supply> psy,
      power_supply_property psp, Ptr<power_supply_propval> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean power_supply_has_property(Ptr<power_supply> psy,
      power_supply_property psp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_hwmon_is_visible((const void*)$arg1, $arg2, $arg3, $arg4)")
  public static @Unsigned @OriginalName("umode_t") short power_supply_hwmon_is_visible(Ptr<?> data,
      hwmon_sensor_types type, @Unsigned int attr, int channel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int power_supply_hwmon_read(Ptr<device> dev, hwmon_sensor_types type,
      @Unsigned int attr, int channel, Ptr<java.lang.Long> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_hwmon_read_string($arg1, $arg2, $arg3, $arg4, (const u8**)$arg5)")
  public static int power_supply_hwmon_read_string(Ptr<device> dev, hwmon_sensor_types type,
      @Unsigned int attr, int channel, Ptr<String> str) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int power_supply_hwmon_to_property(hwmon_sensor_types type, @Unsigned int attr,
      int channel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int power_supply_hwmon_write(Ptr<device> dev, hwmon_sensor_types type,
      @Unsigned int attr, int channel, long val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void power_supply_init_attrs() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int power_supply_is_system_supplied() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int power_supply_led_trigger_activate(Ptr<led_classdev> led_cdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_match_device_by_name($arg1, (const void*)$arg2)")
  public static int power_supply_match_device_by_name(Ptr<device> dev, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_match_device_fwnode($arg1, (const void*)$arg2)")
  public static int power_supply_match_device_fwnode(Ptr<device> dev, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_ocv2cap_simple((const struct power_supply_battery_ocv_table*)$arg1, $arg2, $arg3)")
  public static int power_supply_ocv2cap_simple(Ptr<power_supply_battery_ocv_table> table,
      int table_len, int ocv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int power_supply_powers(Ptr<power_supply> psy, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int power_supply_property_is_writeable(Ptr<power_supply> psy,
      power_supply_property psp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void power_supply_put(Ptr<power_supply> psy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void power_supply_put_battery_info(Ptr<power_supply> psy,
      Ptr<power_supply_battery_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int power_supply_read_temp(Ptr<thermal_zone_device> tzd,
      Ptr<java.lang.Integer> temp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int power_supply_reg_notifier(Ptr<notifier_block> nb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_register($arg1, (const struct power_supply_desc*)$arg2, (const struct power_supply_config*)$arg3)")
  public static Ptr<power_supply> power_supply_register(Ptr<device> parent,
      Ptr<power_supply_desc> desc, Ptr<power_supply_config> cfg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_register_extension($arg1, (const struct power_supply_ext*)$arg2, $arg3, $arg4)")
  public static int power_supply_register_extension(Ptr<power_supply> psy,
      Ptr<power_supply_ext> ext, Ptr<device> dev, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_register_led_trigger($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static int power_supply_register_led_trigger(Ptr<power_supply> psy, String name_template,
      Ptr<Ptr<led_trigger>> tp, Ptr<java.lang.Integer> err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void power_supply_remove_bat_triggers(Ptr<power_supply> psy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void power_supply_remove_hwmon_sysfs(Ptr<power_supply> psy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void power_supply_remove_triggers(Ptr<power_supply> psy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_set_property($arg1, $arg2, (const union power_supply_propval*)$arg3)")
  public static int power_supply_set_property(Ptr<power_supply> psy, power_supply_property psp,
      Ptr<power_supply_propval> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_set_property_direct($arg1, $arg2, (const union power_supply_propval*)$arg3)")
  public static int power_supply_set_property_direct(Ptr<power_supply> psy,
      power_supply_property psp, Ptr<power_supply_propval> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_show_enum_with_available($arg1, (const u8**)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static @OriginalName("ssize_t") long power_supply_show_enum_with_available(Ptr<device> dev,
      Ptr<String> labels, int label_count, @Unsigned int available_values, int value, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long power_supply_show_property(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_store_property($arg1, $arg2, (const u8*)$arg3, $arg4)")
  public static @OriginalName("ssize_t") long power_supply_store_property(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_sysfs_add_extension($arg1, (const struct power_supply_ext*)$arg2, $arg3)")
  public static int power_supply_sysfs_add_extension(Ptr<power_supply> psy,
      Ptr<power_supply_ext> ext, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_sysfs_remove_extension($arg1, (const struct power_supply_ext*)$arg2)")
  public static void power_supply_sysfs_remove_extension(Ptr<power_supply> psy,
      Ptr<power_supply_ext> ext) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_temp2resist_simple((const struct power_supply_resistance_temp_table*)$arg1, $arg2, $arg3)")
  public static int power_supply_temp2resist_simple(Ptr<power_supply_resistance_temp_table> table,
      int table_len, int temp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_uevent((const struct device*)$arg1, $arg2)")
  public static int power_supply_uevent(Ptr<device> dev, Ptr<kobj_uevent_env> env) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void power_supply_unreg_notifier(Ptr<notifier_block> nb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void power_supply_unregister(Ptr<power_supply> psy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_supply_unregister_extension($arg1, (const struct power_supply_ext*)$arg2)")
  public static void power_supply_unregister_extension(Ptr<power_supply> psy,
      Ptr<power_supply_ext> ext) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void power_supply_update_bat_leds(Ptr<power_supply> psy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void power_supply_update_leds(Ptr<power_supply> psy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int power_supply_vbat2ri(Ptr<power_supply_battery_info> info, int vbat_uv,
      boolean charging) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long power_uw_show(Ptr<device> dev,
      Ptr<device_attribute> dev_attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("power_write_file($arg1, (const u8*)$arg2, $arg3)")
  public static @OriginalName("ssize_t") long power_write_file(Ptr<pci_slot> pci_slot, String buf,
      @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int type; unsigned int system_level; unsigned int resource_order; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class power_resource_of_acpi_object extends Struct {
    public @Unsigned @OriginalName("acpi_object_type") int type;

    public @Unsigned int system_level;

    public @Unsigned int resource_order;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum power_supply_property"
  )
  public enum power_supply_property implements Enum<power_supply_property>, TypedEnum<power_supply_property, java.lang. @Unsigned Integer> {
    /**
     * {@code POWER_SUPPLY_PROP_STATUS = 0}
     */
    @EnumMember(
        value = 0L,
        name = "POWER_SUPPLY_PROP_STATUS"
    )
    POWER_SUPPLY_PROP_STATUS,

    /**
     * {@code POWER_SUPPLY_PROP_CHARGE_TYPE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "POWER_SUPPLY_PROP_CHARGE_TYPE"
    )
    POWER_SUPPLY_PROP_CHARGE_TYPE,

    /**
     * {@code POWER_SUPPLY_PROP_CHARGE_TYPES = 2}
     */
    @EnumMember(
        value = 2L,
        name = "POWER_SUPPLY_PROP_CHARGE_TYPES"
    )
    POWER_SUPPLY_PROP_CHARGE_TYPES,

    /**
     * {@code POWER_SUPPLY_PROP_HEALTH = 3}
     */
    @EnumMember(
        value = 3L,
        name = "POWER_SUPPLY_PROP_HEALTH"
    )
    POWER_SUPPLY_PROP_HEALTH,

    /**
     * {@code POWER_SUPPLY_PROP_PRESENT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "POWER_SUPPLY_PROP_PRESENT"
    )
    POWER_SUPPLY_PROP_PRESENT,

    /**
     * {@code POWER_SUPPLY_PROP_ONLINE = 5}
     */
    @EnumMember(
        value = 5L,
        name = "POWER_SUPPLY_PROP_ONLINE"
    )
    POWER_SUPPLY_PROP_ONLINE,

    /**
     * {@code POWER_SUPPLY_PROP_AUTHENTIC = 6}
     */
    @EnumMember(
        value = 6L,
        name = "POWER_SUPPLY_PROP_AUTHENTIC"
    )
    POWER_SUPPLY_PROP_AUTHENTIC,

    /**
     * {@code POWER_SUPPLY_PROP_TECHNOLOGY = 7}
     */
    @EnumMember(
        value = 7L,
        name = "POWER_SUPPLY_PROP_TECHNOLOGY"
    )
    POWER_SUPPLY_PROP_TECHNOLOGY,

    /**
     * {@code POWER_SUPPLY_PROP_CYCLE_COUNT = 8}
     */
    @EnumMember(
        value = 8L,
        name = "POWER_SUPPLY_PROP_CYCLE_COUNT"
    )
    POWER_SUPPLY_PROP_CYCLE_COUNT,

    /**
     * {@code POWER_SUPPLY_PROP_VOLTAGE_MAX = 9}
     */
    @EnumMember(
        value = 9L,
        name = "POWER_SUPPLY_PROP_VOLTAGE_MAX"
    )
    POWER_SUPPLY_PROP_VOLTAGE_MAX,

    /**
     * {@code POWER_SUPPLY_PROP_VOLTAGE_MIN = 10}
     */
    @EnumMember(
        value = 10L,
        name = "POWER_SUPPLY_PROP_VOLTAGE_MIN"
    )
    POWER_SUPPLY_PROP_VOLTAGE_MIN,

    /**
     * {@code POWER_SUPPLY_PROP_VOLTAGE_MAX_DESIGN = 11}
     */
    @EnumMember(
        value = 11L,
        name = "POWER_SUPPLY_PROP_VOLTAGE_MAX_DESIGN"
    )
    POWER_SUPPLY_PROP_VOLTAGE_MAX_DESIGN,

    /**
     * {@code POWER_SUPPLY_PROP_VOLTAGE_MIN_DESIGN = 12}
     */
    @EnumMember(
        value = 12L,
        name = "POWER_SUPPLY_PROP_VOLTAGE_MIN_DESIGN"
    )
    POWER_SUPPLY_PROP_VOLTAGE_MIN_DESIGN,

    /**
     * {@code POWER_SUPPLY_PROP_VOLTAGE_NOW = 13}
     */
    @EnumMember(
        value = 13L,
        name = "POWER_SUPPLY_PROP_VOLTAGE_NOW"
    )
    POWER_SUPPLY_PROP_VOLTAGE_NOW,

    /**
     * {@code POWER_SUPPLY_PROP_VOLTAGE_AVG = 14}
     */
    @EnumMember(
        value = 14L,
        name = "POWER_SUPPLY_PROP_VOLTAGE_AVG"
    )
    POWER_SUPPLY_PROP_VOLTAGE_AVG,

    /**
     * {@code POWER_SUPPLY_PROP_VOLTAGE_OCV = 15}
     */
    @EnumMember(
        value = 15L,
        name = "POWER_SUPPLY_PROP_VOLTAGE_OCV"
    )
    POWER_SUPPLY_PROP_VOLTAGE_OCV,

    /**
     * {@code POWER_SUPPLY_PROP_VOLTAGE_BOOT = 16}
     */
    @EnumMember(
        value = 16L,
        name = "POWER_SUPPLY_PROP_VOLTAGE_BOOT"
    )
    POWER_SUPPLY_PROP_VOLTAGE_BOOT,

    /**
     * {@code POWER_SUPPLY_PROP_CURRENT_MAX = 17}
     */
    @EnumMember(
        value = 17L,
        name = "POWER_SUPPLY_PROP_CURRENT_MAX"
    )
    POWER_SUPPLY_PROP_CURRENT_MAX,

    /**
     * {@code POWER_SUPPLY_PROP_CURRENT_NOW = 18}
     */
    @EnumMember(
        value = 18L,
        name = "POWER_SUPPLY_PROP_CURRENT_NOW"
    )
    POWER_SUPPLY_PROP_CURRENT_NOW,

    /**
     * {@code POWER_SUPPLY_PROP_CURRENT_AVG = 19}
     */
    @EnumMember(
        value = 19L,
        name = "POWER_SUPPLY_PROP_CURRENT_AVG"
    )
    POWER_SUPPLY_PROP_CURRENT_AVG,

    /**
     * {@code POWER_SUPPLY_PROP_CURRENT_BOOT = 20}
     */
    @EnumMember(
        value = 20L,
        name = "POWER_SUPPLY_PROP_CURRENT_BOOT"
    )
    POWER_SUPPLY_PROP_CURRENT_BOOT,

    /**
     * {@code POWER_SUPPLY_PROP_POWER_NOW = 21}
     */
    @EnumMember(
        value = 21L,
        name = "POWER_SUPPLY_PROP_POWER_NOW"
    )
    POWER_SUPPLY_PROP_POWER_NOW,

    /**
     * {@code POWER_SUPPLY_PROP_POWER_AVG = 22}
     */
    @EnumMember(
        value = 22L,
        name = "POWER_SUPPLY_PROP_POWER_AVG"
    )
    POWER_SUPPLY_PROP_POWER_AVG,

    /**
     * {@code POWER_SUPPLY_PROP_CHARGE_FULL_DESIGN = 23}
     */
    @EnumMember(
        value = 23L,
        name = "POWER_SUPPLY_PROP_CHARGE_FULL_DESIGN"
    )
    POWER_SUPPLY_PROP_CHARGE_FULL_DESIGN,

    /**
     * {@code POWER_SUPPLY_PROP_CHARGE_EMPTY_DESIGN = 24}
     */
    @EnumMember(
        value = 24L,
        name = "POWER_SUPPLY_PROP_CHARGE_EMPTY_DESIGN"
    )
    POWER_SUPPLY_PROP_CHARGE_EMPTY_DESIGN,

    /**
     * {@code POWER_SUPPLY_PROP_CHARGE_FULL = 25}
     */
    @EnumMember(
        value = 25L,
        name = "POWER_SUPPLY_PROP_CHARGE_FULL"
    )
    POWER_SUPPLY_PROP_CHARGE_FULL,

    /**
     * {@code POWER_SUPPLY_PROP_CHARGE_EMPTY = 26}
     */
    @EnumMember(
        value = 26L,
        name = "POWER_SUPPLY_PROP_CHARGE_EMPTY"
    )
    POWER_SUPPLY_PROP_CHARGE_EMPTY,

    /**
     * {@code POWER_SUPPLY_PROP_CHARGE_NOW = 27}
     */
    @EnumMember(
        value = 27L,
        name = "POWER_SUPPLY_PROP_CHARGE_NOW"
    )
    POWER_SUPPLY_PROP_CHARGE_NOW,

    /**
     * {@code POWER_SUPPLY_PROP_CHARGE_AVG = 28}
     */
    @EnumMember(
        value = 28L,
        name = "POWER_SUPPLY_PROP_CHARGE_AVG"
    )
    POWER_SUPPLY_PROP_CHARGE_AVG,

    /**
     * {@code POWER_SUPPLY_PROP_CHARGE_COUNTER = 29}
     */
    @EnumMember(
        value = 29L,
        name = "POWER_SUPPLY_PROP_CHARGE_COUNTER"
    )
    POWER_SUPPLY_PROP_CHARGE_COUNTER,

    /**
     * {@code POWER_SUPPLY_PROP_CONSTANT_CHARGE_CURRENT = 30}
     */
    @EnumMember(
        value = 30L,
        name = "POWER_SUPPLY_PROP_CONSTANT_CHARGE_CURRENT"
    )
    POWER_SUPPLY_PROP_CONSTANT_CHARGE_CURRENT,

    /**
     * {@code POWER_SUPPLY_PROP_CONSTANT_CHARGE_CURRENT_MAX = 31}
     */
    @EnumMember(
        value = 31L,
        name = "POWER_SUPPLY_PROP_CONSTANT_CHARGE_CURRENT_MAX"
    )
    POWER_SUPPLY_PROP_CONSTANT_CHARGE_CURRENT_MAX,

    /**
     * {@code POWER_SUPPLY_PROP_CONSTANT_CHARGE_VOLTAGE = 32}
     */
    @EnumMember(
        value = 32L,
        name = "POWER_SUPPLY_PROP_CONSTANT_CHARGE_VOLTAGE"
    )
    POWER_SUPPLY_PROP_CONSTANT_CHARGE_VOLTAGE,

    /**
     * {@code POWER_SUPPLY_PROP_CONSTANT_CHARGE_VOLTAGE_MAX = 33}
     */
    @EnumMember(
        value = 33L,
        name = "POWER_SUPPLY_PROP_CONSTANT_CHARGE_VOLTAGE_MAX"
    )
    POWER_SUPPLY_PROP_CONSTANT_CHARGE_VOLTAGE_MAX,

    /**
     * {@code POWER_SUPPLY_PROP_CHARGE_CONTROL_LIMIT = 34}
     */
    @EnumMember(
        value = 34L,
        name = "POWER_SUPPLY_PROP_CHARGE_CONTROL_LIMIT"
    )
    POWER_SUPPLY_PROP_CHARGE_CONTROL_LIMIT,

    /**
     * {@code POWER_SUPPLY_PROP_CHARGE_CONTROL_LIMIT_MAX = 35}
     */
    @EnumMember(
        value = 35L,
        name = "POWER_SUPPLY_PROP_CHARGE_CONTROL_LIMIT_MAX"
    )
    POWER_SUPPLY_PROP_CHARGE_CONTROL_LIMIT_MAX,

    /**
     * {@code POWER_SUPPLY_PROP_CHARGE_CONTROL_START_THRESHOLD = 36}
     */
    @EnumMember(
        value = 36L,
        name = "POWER_SUPPLY_PROP_CHARGE_CONTROL_START_THRESHOLD"
    )
    POWER_SUPPLY_PROP_CHARGE_CONTROL_START_THRESHOLD,

    /**
     * {@code POWER_SUPPLY_PROP_CHARGE_CONTROL_END_THRESHOLD = 37}
     */
    @EnumMember(
        value = 37L,
        name = "POWER_SUPPLY_PROP_CHARGE_CONTROL_END_THRESHOLD"
    )
    POWER_SUPPLY_PROP_CHARGE_CONTROL_END_THRESHOLD,

    /**
     * {@code POWER_SUPPLY_PROP_CHARGE_BEHAVIOUR = 38}
     */
    @EnumMember(
        value = 38L,
        name = "POWER_SUPPLY_PROP_CHARGE_BEHAVIOUR"
    )
    POWER_SUPPLY_PROP_CHARGE_BEHAVIOUR,

    /**
     * {@code POWER_SUPPLY_PROP_INPUT_CURRENT_LIMIT = 39}
     */
    @EnumMember(
        value = 39L,
        name = "POWER_SUPPLY_PROP_INPUT_CURRENT_LIMIT"
    )
    POWER_SUPPLY_PROP_INPUT_CURRENT_LIMIT,

    /**
     * {@code POWER_SUPPLY_PROP_INPUT_VOLTAGE_LIMIT = 40}
     */
    @EnumMember(
        value = 40L,
        name = "POWER_SUPPLY_PROP_INPUT_VOLTAGE_LIMIT"
    )
    POWER_SUPPLY_PROP_INPUT_VOLTAGE_LIMIT,

    /**
     * {@code POWER_SUPPLY_PROP_INPUT_POWER_LIMIT = 41}
     */
    @EnumMember(
        value = 41L,
        name = "POWER_SUPPLY_PROP_INPUT_POWER_LIMIT"
    )
    POWER_SUPPLY_PROP_INPUT_POWER_LIMIT,

    /**
     * {@code POWER_SUPPLY_PROP_ENERGY_FULL_DESIGN = 42}
     */
    @EnumMember(
        value = 42L,
        name = "POWER_SUPPLY_PROP_ENERGY_FULL_DESIGN"
    )
    POWER_SUPPLY_PROP_ENERGY_FULL_DESIGN,

    /**
     * {@code POWER_SUPPLY_PROP_ENERGY_EMPTY_DESIGN = 43}
     */
    @EnumMember(
        value = 43L,
        name = "POWER_SUPPLY_PROP_ENERGY_EMPTY_DESIGN"
    )
    POWER_SUPPLY_PROP_ENERGY_EMPTY_DESIGN,

    /**
     * {@code POWER_SUPPLY_PROP_ENERGY_FULL = 44}
     */
    @EnumMember(
        value = 44L,
        name = "POWER_SUPPLY_PROP_ENERGY_FULL"
    )
    POWER_SUPPLY_PROP_ENERGY_FULL,

    /**
     * {@code POWER_SUPPLY_PROP_ENERGY_EMPTY = 45}
     */
    @EnumMember(
        value = 45L,
        name = "POWER_SUPPLY_PROP_ENERGY_EMPTY"
    )
    POWER_SUPPLY_PROP_ENERGY_EMPTY,

    /**
     * {@code POWER_SUPPLY_PROP_ENERGY_NOW = 46}
     */
    @EnumMember(
        value = 46L,
        name = "POWER_SUPPLY_PROP_ENERGY_NOW"
    )
    POWER_SUPPLY_PROP_ENERGY_NOW,

    /**
     * {@code POWER_SUPPLY_PROP_ENERGY_AVG = 47}
     */
    @EnumMember(
        value = 47L,
        name = "POWER_SUPPLY_PROP_ENERGY_AVG"
    )
    POWER_SUPPLY_PROP_ENERGY_AVG,

    /**
     * {@code POWER_SUPPLY_PROP_CAPACITY = 48}
     */
    @EnumMember(
        value = 48L,
        name = "POWER_SUPPLY_PROP_CAPACITY"
    )
    POWER_SUPPLY_PROP_CAPACITY,

    /**
     * {@code POWER_SUPPLY_PROP_CAPACITY_ALERT_MIN = 49}
     */
    @EnumMember(
        value = 49L,
        name = "POWER_SUPPLY_PROP_CAPACITY_ALERT_MIN"
    )
    POWER_SUPPLY_PROP_CAPACITY_ALERT_MIN,

    /**
     * {@code POWER_SUPPLY_PROP_CAPACITY_ALERT_MAX = 50}
     */
    @EnumMember(
        value = 50L,
        name = "POWER_SUPPLY_PROP_CAPACITY_ALERT_MAX"
    )
    POWER_SUPPLY_PROP_CAPACITY_ALERT_MAX,

    /**
     * {@code POWER_SUPPLY_PROP_CAPACITY_ERROR_MARGIN = 51}
     */
    @EnumMember(
        value = 51L,
        name = "POWER_SUPPLY_PROP_CAPACITY_ERROR_MARGIN"
    )
    POWER_SUPPLY_PROP_CAPACITY_ERROR_MARGIN,

    /**
     * {@code POWER_SUPPLY_PROP_CAPACITY_LEVEL = 52}
     */
    @EnumMember(
        value = 52L,
        name = "POWER_SUPPLY_PROP_CAPACITY_LEVEL"
    )
    POWER_SUPPLY_PROP_CAPACITY_LEVEL,

    /**
     * {@code POWER_SUPPLY_PROP_TEMP = 53}
     */
    @EnumMember(
        value = 53L,
        name = "POWER_SUPPLY_PROP_TEMP"
    )
    POWER_SUPPLY_PROP_TEMP,

    /**
     * {@code POWER_SUPPLY_PROP_TEMP_MAX = 54}
     */
    @EnumMember(
        value = 54L,
        name = "POWER_SUPPLY_PROP_TEMP_MAX"
    )
    POWER_SUPPLY_PROP_TEMP_MAX,

    /**
     * {@code POWER_SUPPLY_PROP_TEMP_MIN = 55}
     */
    @EnumMember(
        value = 55L,
        name = "POWER_SUPPLY_PROP_TEMP_MIN"
    )
    POWER_SUPPLY_PROP_TEMP_MIN,

    /**
     * {@code POWER_SUPPLY_PROP_TEMP_ALERT_MIN = 56}
     */
    @EnumMember(
        value = 56L,
        name = "POWER_SUPPLY_PROP_TEMP_ALERT_MIN"
    )
    POWER_SUPPLY_PROP_TEMP_ALERT_MIN,

    /**
     * {@code POWER_SUPPLY_PROP_TEMP_ALERT_MAX = 57}
     */
    @EnumMember(
        value = 57L,
        name = "POWER_SUPPLY_PROP_TEMP_ALERT_MAX"
    )
    POWER_SUPPLY_PROP_TEMP_ALERT_MAX,

    /**
     * {@code POWER_SUPPLY_PROP_TEMP_AMBIENT = 58}
     */
    @EnumMember(
        value = 58L,
        name = "POWER_SUPPLY_PROP_TEMP_AMBIENT"
    )
    POWER_SUPPLY_PROP_TEMP_AMBIENT,

    /**
     * {@code POWER_SUPPLY_PROP_TEMP_AMBIENT_ALERT_MIN = 59}
     */
    @EnumMember(
        value = 59L,
        name = "POWER_SUPPLY_PROP_TEMP_AMBIENT_ALERT_MIN"
    )
    POWER_SUPPLY_PROP_TEMP_AMBIENT_ALERT_MIN,

    /**
     * {@code POWER_SUPPLY_PROP_TEMP_AMBIENT_ALERT_MAX = 60}
     */
    @EnumMember(
        value = 60L,
        name = "POWER_SUPPLY_PROP_TEMP_AMBIENT_ALERT_MAX"
    )
    POWER_SUPPLY_PROP_TEMP_AMBIENT_ALERT_MAX,

    /**
     * {@code POWER_SUPPLY_PROP_TIME_TO_EMPTY_NOW = 61}
     */
    @EnumMember(
        value = 61L,
        name = "POWER_SUPPLY_PROP_TIME_TO_EMPTY_NOW"
    )
    POWER_SUPPLY_PROP_TIME_TO_EMPTY_NOW,

    /**
     * {@code POWER_SUPPLY_PROP_TIME_TO_EMPTY_AVG = 62}
     */
    @EnumMember(
        value = 62L,
        name = "POWER_SUPPLY_PROP_TIME_TO_EMPTY_AVG"
    )
    POWER_SUPPLY_PROP_TIME_TO_EMPTY_AVG,

    /**
     * {@code POWER_SUPPLY_PROP_TIME_TO_FULL_NOW = 63}
     */
    @EnumMember(
        value = 63L,
        name = "POWER_SUPPLY_PROP_TIME_TO_FULL_NOW"
    )
    POWER_SUPPLY_PROP_TIME_TO_FULL_NOW,

    /**
     * {@code POWER_SUPPLY_PROP_TIME_TO_FULL_AVG = 64}
     */
    @EnumMember(
        value = 64L,
        name = "POWER_SUPPLY_PROP_TIME_TO_FULL_AVG"
    )
    POWER_SUPPLY_PROP_TIME_TO_FULL_AVG,

    /**
     * {@code POWER_SUPPLY_PROP_TYPE = 65}
     */
    @EnumMember(
        value = 65L,
        name = "POWER_SUPPLY_PROP_TYPE"
    )
    POWER_SUPPLY_PROP_TYPE,

    /**
     * {@code POWER_SUPPLY_PROP_USB_TYPE = 66}
     */
    @EnumMember(
        value = 66L,
        name = "POWER_SUPPLY_PROP_USB_TYPE"
    )
    POWER_SUPPLY_PROP_USB_TYPE,

    /**
     * {@code POWER_SUPPLY_PROP_SCOPE = 67}
     */
    @EnumMember(
        value = 67L,
        name = "POWER_SUPPLY_PROP_SCOPE"
    )
    POWER_SUPPLY_PROP_SCOPE,

    /**
     * {@code POWER_SUPPLY_PROP_PRECHARGE_CURRENT = 68}
     */
    @EnumMember(
        value = 68L,
        name = "POWER_SUPPLY_PROP_PRECHARGE_CURRENT"
    )
    POWER_SUPPLY_PROP_PRECHARGE_CURRENT,

    /**
     * {@code POWER_SUPPLY_PROP_CHARGE_TERM_CURRENT = 69}
     */
    @EnumMember(
        value = 69L,
        name = "POWER_SUPPLY_PROP_CHARGE_TERM_CURRENT"
    )
    POWER_SUPPLY_PROP_CHARGE_TERM_CURRENT,

    /**
     * {@code POWER_SUPPLY_PROP_CALIBRATE = 70}
     */
    @EnumMember(
        value = 70L,
        name = "POWER_SUPPLY_PROP_CALIBRATE"
    )
    POWER_SUPPLY_PROP_CALIBRATE,

    /**
     * {@code POWER_SUPPLY_PROP_MANUFACTURE_YEAR = 71}
     */
    @EnumMember(
        value = 71L,
        name = "POWER_SUPPLY_PROP_MANUFACTURE_YEAR"
    )
    POWER_SUPPLY_PROP_MANUFACTURE_YEAR,

    /**
     * {@code POWER_SUPPLY_PROP_MANUFACTURE_MONTH = 72}
     */
    @EnumMember(
        value = 72L,
        name = "POWER_SUPPLY_PROP_MANUFACTURE_MONTH"
    )
    POWER_SUPPLY_PROP_MANUFACTURE_MONTH,

    /**
     * {@code POWER_SUPPLY_PROP_MANUFACTURE_DAY = 73}
     */
    @EnumMember(
        value = 73L,
        name = "POWER_SUPPLY_PROP_MANUFACTURE_DAY"
    )
    POWER_SUPPLY_PROP_MANUFACTURE_DAY,

    /**
     * {@code POWER_SUPPLY_PROP_MODEL_NAME = 74}
     */
    @EnumMember(
        value = 74L,
        name = "POWER_SUPPLY_PROP_MODEL_NAME"
    )
    POWER_SUPPLY_PROP_MODEL_NAME,

    /**
     * {@code POWER_SUPPLY_PROP_MANUFACTURER = 75}
     */
    @EnumMember(
        value = 75L,
        name = "POWER_SUPPLY_PROP_MANUFACTURER"
    )
    POWER_SUPPLY_PROP_MANUFACTURER,

    /**
     * {@code POWER_SUPPLY_PROP_SERIAL_NUMBER = 76}
     */
    @EnumMember(
        value = 76L,
        name = "POWER_SUPPLY_PROP_SERIAL_NUMBER"
    )
    POWER_SUPPLY_PROP_SERIAL_NUMBER
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum power_supply_type"
  )
  public enum power_supply_type implements Enum<power_supply_type>, TypedEnum<power_supply_type, java.lang. @Unsigned Integer> {
    /**
     * {@code POWER_SUPPLY_TYPE_UNKNOWN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "POWER_SUPPLY_TYPE_UNKNOWN"
    )
    POWER_SUPPLY_TYPE_UNKNOWN,

    /**
     * {@code POWER_SUPPLY_TYPE_BATTERY = 1}
     */
    @EnumMember(
        value = 1L,
        name = "POWER_SUPPLY_TYPE_BATTERY"
    )
    POWER_SUPPLY_TYPE_BATTERY,

    /**
     * {@code POWER_SUPPLY_TYPE_UPS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "POWER_SUPPLY_TYPE_UPS"
    )
    POWER_SUPPLY_TYPE_UPS,

    /**
     * {@code POWER_SUPPLY_TYPE_MAINS = 3}
     */
    @EnumMember(
        value = 3L,
        name = "POWER_SUPPLY_TYPE_MAINS"
    )
    POWER_SUPPLY_TYPE_MAINS,

    /**
     * {@code POWER_SUPPLY_TYPE_USB = 4}
     */
    @EnumMember(
        value = 4L,
        name = "POWER_SUPPLY_TYPE_USB"
    )
    POWER_SUPPLY_TYPE_USB,

    /**
     * {@code POWER_SUPPLY_TYPE_USB_DCP = 5}
     */
    @EnumMember(
        value = 5L,
        name = "POWER_SUPPLY_TYPE_USB_DCP"
    )
    POWER_SUPPLY_TYPE_USB_DCP,

    /**
     * {@code POWER_SUPPLY_TYPE_USB_CDP = 6}
     */
    @EnumMember(
        value = 6L,
        name = "POWER_SUPPLY_TYPE_USB_CDP"
    )
    POWER_SUPPLY_TYPE_USB_CDP,

    /**
     * {@code POWER_SUPPLY_TYPE_USB_ACA = 7}
     */
    @EnumMember(
        value = 7L,
        name = "POWER_SUPPLY_TYPE_USB_ACA"
    )
    POWER_SUPPLY_TYPE_USB_ACA,

    /**
     * {@code POWER_SUPPLY_TYPE_USB_TYPE_C = 8}
     */
    @EnumMember(
        value = 8L,
        name = "POWER_SUPPLY_TYPE_USB_TYPE_C"
    )
    POWER_SUPPLY_TYPE_USB_TYPE_C,

    /**
     * {@code POWER_SUPPLY_TYPE_USB_PD = 9}
     */
    @EnumMember(
        value = 9L,
        name = "POWER_SUPPLY_TYPE_USB_PD"
    )
    POWER_SUPPLY_TYPE_USB_PD,

    /**
     * {@code POWER_SUPPLY_TYPE_USB_PD_DRP = 10}
     */
    @EnumMember(
        value = 10L,
        name = "POWER_SUPPLY_TYPE_USB_PD_DRP"
    )
    POWER_SUPPLY_TYPE_USB_PD_DRP,

    /**
     * {@code POWER_SUPPLY_TYPE_APPLE_BRICK_ID = 11}
     */
    @EnumMember(
        value = 11L,
        name = "POWER_SUPPLY_TYPE_APPLE_BRICK_ID"
    )
    POWER_SUPPLY_TYPE_APPLE_BRICK_ID,

    /**
     * {@code POWER_SUPPLY_TYPE_WIRELESS = 12}
     */
    @EnumMember(
        value = 12L,
        name = "POWER_SUPPLY_TYPE_WIRELESS"
    )
    POWER_SUPPLY_TYPE_WIRELESS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union power_supply_propval"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class power_supply_propval extends Union {
    public int intval;

    public String strval;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct power_supply_config"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class power_supply_config extends Struct {
    public Ptr<fwnode_handle> fwnode;

    public Ptr<?> drv_data;

    public Ptr<Ptr<attribute_group>> attr_grp;

    public Ptr<String> supplied_to;

    public @Unsigned long num_supplicants;

    public boolean no_wakeup_source;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct power_supply_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class power_supply_desc extends Struct {
    public String name;

    public power_supply_type type;

    public char charge_behaviours;

    public @Unsigned int charge_types;

    public @Unsigned int usb_types;

    public Ptr<power_supply_property> properties;

    public @Unsigned long num_properties;

    public Ptr<?> get_property;

    public Ptr<?> set_property;

    public Ptr<?> property_is_writeable;

    public Ptr<?> external_power_changed;

    public boolean no_thermal;

    public int use_for_apm;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct power_supply"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class power_supply extends Struct {
    public Ptr<power_supply_desc> desc;

    public Ptr<String> supplied_to;

    public @Unsigned long num_supplicants;

    public Ptr<String> supplied_from;

    public @Unsigned long num_supplies;

    public Ptr<?> drv_data;

    public device dev;

    public work_struct changed_work;

    public delayed_work deferred_register_work;

    public @OriginalName("spinlock_t") spinlock changed_lock;

    public boolean changed;

    public boolean update_groups;

    public boolean initialized;

    public boolean removing;

    public atomic_t use_cnt;

    public Ptr<power_supply_battery_info> battery_info;

    public rw_semaphore extensions_sem;

    public list_head extensions;

    public Ptr<thermal_zone_device> tzd;

    public Ptr<thermal_cooling_device> tcd;

    public Ptr<led_trigger> trig;

    public Ptr<led_trigger> charging_trig;

    public Ptr<led_trigger> full_trig;

    public Ptr<led_trigger> charging_blink_full_solid_trig;

    public Ptr<led_trigger> charging_orange_full_green_trig;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct power_supply_battery_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class power_supply_battery_info extends Struct {
    public @Unsigned int technology;

    public int energy_full_design_uwh;

    public int charge_full_design_uah;

    public int voltage_min_design_uv;

    public int voltage_max_design_uv;

    public int tricklecharge_current_ua;

    public int precharge_current_ua;

    public int precharge_voltage_max_uv;

    public int charge_term_current_ua;

    public int charge_restart_voltage_uv;

    public int overvoltage_limit_uv;

    public int constant_charge_current_max_ua;

    public int constant_charge_voltage_max_uv;

    public Ptr<power_supply_maintenance_charge_table> maintenance_charge;

    public int maintenance_charge_size;

    public int alert_low_temp_charge_current_ua;

    public int alert_low_temp_charge_voltage_uv;

    public int alert_high_temp_charge_current_ua;

    public int alert_high_temp_charge_voltage_uv;

    public int factory_internal_resistance_uohm;

    public int factory_internal_resistance_charging_uohm;

    public int @Size(20) [] ocv_temp;

    public int temp_ambient_alert_min;

    public int temp_ambient_alert_max;

    public int temp_alert_min;

    public int temp_alert_max;

    public int temp_min;

    public int temp_max;

    public Ptr<power_supply_battery_ocv_table> @Size(20) [] ocv_table;

    public int @Size(20) [] ocv_table_size;

    public Ptr<power_supply_resistance_temp_table> resist_table;

    public int resist_table_size;

    public Ptr<power_supply_vbat_ri_table> vbat2ri_discharging;

    public int vbat2ri_discharging_size;

    public Ptr<power_supply_vbat_ri_table> vbat2ri_charging;

    public int vbat2ri_charging_size;

    public int bti_resistance_ohm;

    public int bti_resistance_tolerance;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct power_supply_battery_ocv_table"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class power_supply_battery_ocv_table extends Struct {
    public int ocv;

    public int capacity;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct power_supply_resistance_temp_table"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class power_supply_resistance_temp_table extends Struct {
    public int temp;

    public int resistance;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct power_supply_vbat_ri_table"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class power_supply_vbat_ri_table extends Struct {
    public int vbat_uv;

    public int ri_uohm;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct power_supply_maintenance_charge_table"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class power_supply_maintenance_charge_table extends Struct {
    public int charge_current_max_ua;

    public int charge_voltage_max_uv;

    public int charge_safety_timer_minutes;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum power_supply_notifier_events"
  )
  public enum power_supply_notifier_events implements Enum<power_supply_notifier_events>, TypedEnum<power_supply_notifier_events, java.lang. @Unsigned Integer> {
    /**
     * {@code PSY_EVENT_PROP_CHANGED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PSY_EVENT_PROP_CHANGED"
    )
    PSY_EVENT_PROP_CHANGED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct power_supply_ext"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class power_supply_ext extends Struct {
    public String name;

    public char charge_behaviours;

    public @Unsigned int charge_types;

    public Ptr<power_supply_property> properties;

    public @Unsigned long num_properties;

    public Ptr<?> get_property;

    public Ptr<?> set_property;

    public Ptr<?> property_is_writeable;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct power_supply_ext_registration"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class power_supply_ext_registration extends Struct {
    public list_head list_head;

    public Ptr<power_supply_ext> ext;

    public Ptr<device> dev;

    public Ptr<?> data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum power_supply_charge_type"
  )
  public enum power_supply_charge_type implements Enum<power_supply_charge_type>, TypedEnum<power_supply_charge_type, java.lang. @Unsigned Integer> {
    /**
     * {@code POWER_SUPPLY_CHARGE_TYPE_UNKNOWN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "POWER_SUPPLY_CHARGE_TYPE_UNKNOWN"
    )
    POWER_SUPPLY_CHARGE_TYPE_UNKNOWN,

    /**
     * {@code POWER_SUPPLY_CHARGE_TYPE_NONE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "POWER_SUPPLY_CHARGE_TYPE_NONE"
    )
    POWER_SUPPLY_CHARGE_TYPE_NONE,

    /**
     * {@code POWER_SUPPLY_CHARGE_TYPE_TRICKLE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "POWER_SUPPLY_CHARGE_TYPE_TRICKLE"
    )
    POWER_SUPPLY_CHARGE_TYPE_TRICKLE,

    /**
     * {@code POWER_SUPPLY_CHARGE_TYPE_FAST = 3}
     */
    @EnumMember(
        value = 3L,
        name = "POWER_SUPPLY_CHARGE_TYPE_FAST"
    )
    POWER_SUPPLY_CHARGE_TYPE_FAST,

    /**
     * {@code POWER_SUPPLY_CHARGE_TYPE_STANDARD = 4}
     */
    @EnumMember(
        value = 4L,
        name = "POWER_SUPPLY_CHARGE_TYPE_STANDARD"
    )
    POWER_SUPPLY_CHARGE_TYPE_STANDARD,

    /**
     * {@code POWER_SUPPLY_CHARGE_TYPE_ADAPTIVE = 5}
     */
    @EnumMember(
        value = 5L,
        name = "POWER_SUPPLY_CHARGE_TYPE_ADAPTIVE"
    )
    POWER_SUPPLY_CHARGE_TYPE_ADAPTIVE,

    /**
     * {@code POWER_SUPPLY_CHARGE_TYPE_CUSTOM = 6}
     */
    @EnumMember(
        value = 6L,
        name = "POWER_SUPPLY_CHARGE_TYPE_CUSTOM"
    )
    POWER_SUPPLY_CHARGE_TYPE_CUSTOM,

    /**
     * {@code POWER_SUPPLY_CHARGE_TYPE_LONGLIFE = 7}
     */
    @EnumMember(
        value = 7L,
        name = "POWER_SUPPLY_CHARGE_TYPE_LONGLIFE"
    )
    POWER_SUPPLY_CHARGE_TYPE_LONGLIFE,

    /**
     * {@code POWER_SUPPLY_CHARGE_TYPE_BYPASS = 8}
     */
    @EnumMember(
        value = 8L,
        name = "POWER_SUPPLY_CHARGE_TYPE_BYPASS"
    )
    POWER_SUPPLY_CHARGE_TYPE_BYPASS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum power_supply_usb_type"
  )
  public enum power_supply_usb_type implements Enum<power_supply_usb_type>, TypedEnum<power_supply_usb_type, java.lang. @Unsigned Integer> {
    /**
     * {@code POWER_SUPPLY_USB_TYPE_UNKNOWN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "POWER_SUPPLY_USB_TYPE_UNKNOWN"
    )
    POWER_SUPPLY_USB_TYPE_UNKNOWN,

    /**
     * {@code POWER_SUPPLY_USB_TYPE_SDP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "POWER_SUPPLY_USB_TYPE_SDP"
    )
    POWER_SUPPLY_USB_TYPE_SDP,

    /**
     * {@code POWER_SUPPLY_USB_TYPE_DCP = 2}
     */
    @EnumMember(
        value = 2L,
        name = "POWER_SUPPLY_USB_TYPE_DCP"
    )
    POWER_SUPPLY_USB_TYPE_DCP,

    /**
     * {@code POWER_SUPPLY_USB_TYPE_CDP = 3}
     */
    @EnumMember(
        value = 3L,
        name = "POWER_SUPPLY_USB_TYPE_CDP"
    )
    POWER_SUPPLY_USB_TYPE_CDP,

    /**
     * {@code POWER_SUPPLY_USB_TYPE_ACA = 4}
     */
    @EnumMember(
        value = 4L,
        name = "POWER_SUPPLY_USB_TYPE_ACA"
    )
    POWER_SUPPLY_USB_TYPE_ACA,

    /**
     * {@code POWER_SUPPLY_USB_TYPE_C = 5}
     */
    @EnumMember(
        value = 5L,
        name = "POWER_SUPPLY_USB_TYPE_C"
    )
    POWER_SUPPLY_USB_TYPE_C,

    /**
     * {@code POWER_SUPPLY_USB_TYPE_PD = 6}
     */
    @EnumMember(
        value = 6L,
        name = "POWER_SUPPLY_USB_TYPE_PD"
    )
    POWER_SUPPLY_USB_TYPE_PD,

    /**
     * {@code POWER_SUPPLY_USB_TYPE_PD_DRP = 7}
     */
    @EnumMember(
        value = 7L,
        name = "POWER_SUPPLY_USB_TYPE_PD_DRP"
    )
    POWER_SUPPLY_USB_TYPE_PD_DRP,

    /**
     * {@code POWER_SUPPLY_USB_TYPE_PD_PPS = 8}
     */
    @EnumMember(
        value = 8L,
        name = "POWER_SUPPLY_USB_TYPE_PD_PPS"
    )
    POWER_SUPPLY_USB_TYPE_PD_PPS,

    /**
     * {@code POWER_SUPPLY_USB_TYPE_APPLE_BRICK_ID = 9}
     */
    @EnumMember(
        value = 9L,
        name = "POWER_SUPPLY_USB_TYPE_APPLE_BRICK_ID"
    )
    POWER_SUPPLY_USB_TYPE_APPLE_BRICK_ID
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum power_supply_charge_behaviour"
  )
  public enum power_supply_charge_behaviour implements Enum<power_supply_charge_behaviour>, TypedEnum<power_supply_charge_behaviour, java.lang. @Unsigned Integer> {
    /**
     * {@code POWER_SUPPLY_CHARGE_BEHAVIOUR_AUTO = 0}
     */
    @EnumMember(
        value = 0L,
        name = "POWER_SUPPLY_CHARGE_BEHAVIOUR_AUTO"
    )
    POWER_SUPPLY_CHARGE_BEHAVIOUR_AUTO,

    /**
     * {@code POWER_SUPPLY_CHARGE_BEHAVIOUR_INHIBIT_CHARGE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "POWER_SUPPLY_CHARGE_BEHAVIOUR_INHIBIT_CHARGE"
    )
    POWER_SUPPLY_CHARGE_BEHAVIOUR_INHIBIT_CHARGE,

    /**
     * {@code POWER_SUPPLY_CHARGE_BEHAVIOUR_INHIBIT_CHARGE_AWAKE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "POWER_SUPPLY_CHARGE_BEHAVIOUR_INHIBIT_CHARGE_AWAKE"
    )
    POWER_SUPPLY_CHARGE_BEHAVIOUR_INHIBIT_CHARGE_AWAKE,

    /**
     * {@code POWER_SUPPLY_CHARGE_BEHAVIOUR_FORCE_DISCHARGE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "POWER_SUPPLY_CHARGE_BEHAVIOUR_FORCE_DISCHARGE"
    )
    POWER_SUPPLY_CHARGE_BEHAVIOUR_FORCE_DISCHARGE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct power_supply_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class power_supply_attr extends Struct {
    public String prop_name;

    public char @Size(31) [] attr_name;

    public device_attribute dev_attr;

    public Ptr<String> text_values;

    public int text_values_len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct power_supply_led_trigger"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class power_supply_led_trigger extends Struct {
    public led_trigger trig;

    public Ptr<power_supply> psy;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct power_supply_hwmon"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class power_supply_hwmon extends Struct {
    public Ptr<power_supply> psy;

    public Ptr<java.lang. @Unsigned Long> props;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct power_actor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class power_actor extends Struct {
    public @Unsigned int req_power;

    public @Unsigned int max_power;

    public @Unsigned int granted_power;

    public @Unsigned int extra_actor_power;

    public @Unsigned int weighted_req_power;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct power_allocator_params"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class power_allocator_params extends Struct {
    public boolean allocated_tzp;

    public boolean update_cdevs;

    public long err_integral;

    public int prev_err;

    public @Unsigned int sustainable_power;

    public Ptr<thermal_trip> trip_switch_on;

    public Ptr<thermal_trip> trip_max;

    public int total_weight;

    public @Unsigned int num_actors;

    public @Unsigned int buffer_size;

    public Ptr<power_actor> power;
  }
}
